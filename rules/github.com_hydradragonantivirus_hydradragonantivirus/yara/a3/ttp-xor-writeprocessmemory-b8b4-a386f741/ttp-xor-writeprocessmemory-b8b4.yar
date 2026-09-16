rule TTP_XOR_WriteProcessMemory_b8b4 {
  strings:
    $key_b8b4 = { ef c6 [2] dd e4 [2] db d1 [2] f5 d1 [2] ca cd }

  condition:
    any of them
}