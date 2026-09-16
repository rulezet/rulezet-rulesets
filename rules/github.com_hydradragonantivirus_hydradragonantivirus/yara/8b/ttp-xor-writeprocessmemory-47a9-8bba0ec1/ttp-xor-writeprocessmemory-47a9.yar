rule TTP_XOR_WriteProcessMemory_47a9 {
  strings:
    $key_47a9 = { 10 db [2] 22 f9 [2] 24 cc [2] 0a cc [2] 35 d0 }

  condition:
    any of them
}