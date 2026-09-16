rule TTP_XOR_WriteProcessMemory_1ebe {
  strings:
    $key_1ebe = { 49 cc [2] 7b ee [2] 7d db [2] 53 db [2] 6c c7 }

  condition:
    any of them
}