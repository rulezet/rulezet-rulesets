rule TTP_XOR_WriteProcessMemory_b8b0 {
  strings:
    $key_b8b0 = { ef c2 [2] dd e0 [2] db d5 [2] f5 d5 [2] ca c9 }

  condition:
    any of them
}