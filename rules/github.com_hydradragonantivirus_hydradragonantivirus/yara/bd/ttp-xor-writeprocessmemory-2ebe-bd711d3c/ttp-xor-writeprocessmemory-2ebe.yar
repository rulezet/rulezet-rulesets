rule TTP_XOR_WriteProcessMemory_2ebe {
  strings:
    $key_2ebe = { 79 cc [2] 4b ee [2] 4d db [2] 63 db [2] 5c c7 }

  condition:
    any of them
}