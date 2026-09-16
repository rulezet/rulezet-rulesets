rule TTP_XOR_WriteProcessMemory_80c3 {
  strings:
    $key_80c3 = { d7 b1 [2] e5 93 [2] e3 a6 [2] cd a6 [2] f2 ba }

  condition:
    any of them
}