rule TTP_XOR_WriteProcessMemory_2abc {
  strings:
    $key_2abc = { 7d ce [2] 4f ec [2] 49 d9 [2] 67 d9 [2] 58 c5 }

  condition:
    any of them
}