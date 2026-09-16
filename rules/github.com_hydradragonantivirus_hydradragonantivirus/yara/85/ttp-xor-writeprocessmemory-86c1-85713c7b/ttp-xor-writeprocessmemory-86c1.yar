rule TTP_XOR_WriteProcessMemory_86c1 {
  strings:
    $key_86c1 = { d1 b3 [2] e3 91 [2] e5 a4 [2] cb a4 [2] f4 b8 }

  condition:
    any of them
}