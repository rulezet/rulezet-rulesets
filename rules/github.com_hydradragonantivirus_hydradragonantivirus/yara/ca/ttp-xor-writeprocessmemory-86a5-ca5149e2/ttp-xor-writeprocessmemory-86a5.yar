rule TTP_XOR_WriteProcessMemory_86a5 {
  strings:
    $key_86a5 = { d1 d7 [2] e3 f5 [2] e5 c0 [2] cb c0 [2] f4 dc }

  condition:
    any of them
}