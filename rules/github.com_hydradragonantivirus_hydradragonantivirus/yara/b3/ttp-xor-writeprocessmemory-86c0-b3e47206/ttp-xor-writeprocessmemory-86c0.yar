rule TTP_XOR_WriteProcessMemory_86c0 {
  strings:
    $key_86c0 = { d1 b2 [2] e3 90 [2] e5 a5 [2] cb a5 [2] f4 b9 }

  condition:
    any of them
}