rule TTP_XOR_WriteProcessMemory_94d1 {
  strings:
    $key_94d1 = { c3 a3 [2] f1 81 [2] f7 b4 [2] d9 b4 [2] e6 a8 }

  condition:
    any of them
}