rule TTP_XOR_WriteProcessMemory_4a9c {
  strings:
    $key_4a9c = { 1d ee [2] 2f cc [2] 29 f9 [2] 07 f9 [2] 38 e5 }

  condition:
    any of them
}