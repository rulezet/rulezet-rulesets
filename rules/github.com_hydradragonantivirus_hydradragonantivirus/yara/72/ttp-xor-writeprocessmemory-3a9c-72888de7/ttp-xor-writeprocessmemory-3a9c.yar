rule TTP_XOR_WriteProcessMemory_3a9c {
  strings:
    $key_3a9c = { 6d ee [2] 5f cc [2] 59 f9 [2] 77 f9 [2] 48 e5 }

  condition:
    any of them
}