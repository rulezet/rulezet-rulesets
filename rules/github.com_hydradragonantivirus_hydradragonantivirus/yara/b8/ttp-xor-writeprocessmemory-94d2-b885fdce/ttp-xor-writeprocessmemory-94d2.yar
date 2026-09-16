rule TTP_XOR_WriteProcessMemory_94d2 {
  strings:
    $key_94d2 = { c3 a0 [2] f1 82 [2] f7 b7 [2] d9 b7 [2] e6 ab }

  condition:
    any of them
}