rule TTP_XOR_WriteProcessMemory_6ebe {
  strings:
    $key_6ebe = { 39 cc [2] 0b ee [2] 0d db [2] 23 db [2] 1c c7 }

  condition:
    any of them
}