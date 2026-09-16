rule TTP_XOR_WriteProcessMemory_b8bc {
  strings:
    $key_b8bc = { ef ce [2] dd ec [2] db d9 [2] f5 d9 [2] ca c5 }

  condition:
    any of them
}