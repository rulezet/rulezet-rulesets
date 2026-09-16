rule TTP_XOR_WriteProcessMemory_228b {
  strings:
    $key_228b = { 75 f9 [2] 47 db [2] 41 ee [2] 6f ee [2] 50 f2 }

  condition:
    any of them
}