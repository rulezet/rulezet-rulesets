rule TTP_XOR_WriteProcessMemory_2243 {
  strings:
    $key_2243 = { 75 31 [2] 47 13 [2] 41 26 [2] 6f 26 [2] 50 3a }

  condition:
    any of them
}