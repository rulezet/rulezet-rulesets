rule TTP_XOR_WriteProcessMemory_ea94 {
  strings:
    $key_ea94 = { bd e6 [2] 8f c4 [2] 89 f1 [2] a7 f1 [2] 98 ed }

  condition:
    any of them
}