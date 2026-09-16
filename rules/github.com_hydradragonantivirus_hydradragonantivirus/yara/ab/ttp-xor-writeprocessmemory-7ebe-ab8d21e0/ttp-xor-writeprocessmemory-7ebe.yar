rule TTP_XOR_WriteProcessMemory_7ebe {
  strings:
    $key_7ebe = { 29 cc [2] 1b ee [2] 1d db [2] 33 db [2] 0c c7 }

  condition:
    any of them
}