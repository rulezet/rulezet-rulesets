rule TTP_XOR_WriteProcessMemory_86d2 {
  strings:
    $key_86d2 = { d1 a0 [2] e3 82 [2] e5 b7 [2] cb b7 [2] f4 ab }

  condition:
    any of them
}