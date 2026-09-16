rule TTP_XOR_WriteProcessMemory_0abc {
  strings:
    $key_0abc = { 5d ce [2] 6f ec [2] 69 d9 [2] 47 d9 [2] 78 c5 }

  condition:
    any of them
}