rule TTP_XOR_WriteProcessMemory_b8b2 {
  strings:
    $key_b8b2 = { ef c0 [2] dd e2 [2] db d7 [2] f5 d7 [2] ca cb }

  condition:
    any of them
}