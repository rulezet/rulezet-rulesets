rule TTP_XOR_WriteProcessMemory_7abc {
  strings:
    $key_7abc = { 2d ce [2] 1f ec [2] 19 d9 [2] 37 d9 [2] 08 c5 }

  condition:
    any of them
}