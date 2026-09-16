rule TTP_XOR_WriteProcessMemory_3abc {
  strings:
    $key_3abc = { 6d ce [2] 5f ec [2] 59 d9 [2] 77 d9 [2] 48 c5 }

  condition:
    any of them
}