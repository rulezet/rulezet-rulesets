rule TTP_XOR_WriteProcessMemory_86d9 {
  strings:
    $key_86d9 = { d1 ab [2] e3 89 [2] e5 bc [2] cb bc [2] f4 a0 }

  condition:
    any of them
}