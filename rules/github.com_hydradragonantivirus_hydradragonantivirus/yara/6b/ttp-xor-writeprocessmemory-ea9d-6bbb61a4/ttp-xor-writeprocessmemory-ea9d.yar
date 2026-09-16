rule TTP_XOR_WriteProcessMemory_ea9d {
  strings:
    $key_ea9d = { bd ef [2] 8f cd [2] 89 f8 [2] a7 f8 [2] 98 e4 }

  condition:
    any of them
}