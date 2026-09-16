rule TTP_XOR_WriteProcessMemory_3526 {
  strings:
    $key_3526 = { 62 54 [2] 50 76 [2] 56 43 [2] 78 43 [2] 47 5f }

  condition:
    any of them
}