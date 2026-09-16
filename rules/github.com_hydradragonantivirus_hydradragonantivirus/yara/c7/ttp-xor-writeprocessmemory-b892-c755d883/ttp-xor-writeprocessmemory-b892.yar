rule TTP_XOR_WriteProcessMemory_b892 {
  strings:
    $key_b892 = { ef e0 [2] dd c2 [2] db f7 [2] f5 f7 [2] ca eb }

  condition:
    any of them
}