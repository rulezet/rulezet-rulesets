rule TTP_XOR_WriteProcessMemory_6abc {
  strings:
    $key_6abc = { 3d ce [2] 0f ec [2] 09 d9 [2] 27 d9 [2] 18 c5 }

  condition:
    any of them
}