rule TTP_XOR_WriteProcessMemory_ea9c {
  strings:
    $key_ea9c = { bd ee [2] 8f cc [2] 89 f9 [2] a7 f9 [2] 98 e5 }

  condition:
    any of them
}