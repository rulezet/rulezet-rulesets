rule TTP_XOR_WriteProcessMemory_b890 {
  strings:
    $key_b890 = { ef e2 [2] dd c0 [2] db f5 [2] f5 f5 [2] ca e9 }

  condition:
    any of them
}