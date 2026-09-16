rule TTP_XOR_WriteProcessMemory_ea96 {
  strings:
    $key_ea96 = { bd e4 [2] 8f c6 [2] 89 f3 [2] a7 f3 [2] 98 ef }

  condition:
    any of them
}