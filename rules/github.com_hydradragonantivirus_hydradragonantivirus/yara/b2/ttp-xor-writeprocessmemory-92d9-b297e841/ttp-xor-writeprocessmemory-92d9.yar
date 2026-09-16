rule TTP_XOR_WriteProcessMemory_92d9 {
  strings:
    $key_92d9 = { c5 ab [2] f7 89 [2] f1 bc [2] df bc [2] e0 a0 }

  condition:
    any of them
}