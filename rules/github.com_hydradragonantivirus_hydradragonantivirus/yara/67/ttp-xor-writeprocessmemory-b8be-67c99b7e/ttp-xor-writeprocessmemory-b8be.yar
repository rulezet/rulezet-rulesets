rule TTP_XOR_WriteProcessMemory_b8be {
  strings:
    $key_b8be = { ef cc [2] dd ee [2] db db [2] f5 db [2] ca c7 }

  condition:
    any of them
}