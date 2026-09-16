rule TTP_XOR_WriteProcessMemory_86a6 {
  strings:
    $key_86a6 = { d1 d4 [2] e3 f6 [2] e5 c3 [2] cb c3 [2] f4 df }

  condition:
    any of them
}