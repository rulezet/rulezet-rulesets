rule TTP_XOR_WriteProcessMemory_1a9c {
  strings:
    $key_1a9c = { 4d ee [2] 7f cc [2] 79 f9 [2] 57 f9 [2] 68 e5 }

  condition:
    any of them
}