rule TTP_XOR_WriteProcessMemory_ea91 {
  strings:
    $key_ea91 = { bd e3 [2] 8f c1 [2] 89 f4 [2] a7 f4 [2] 98 e8 }

  condition:
    any of them
}