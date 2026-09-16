rule TTP_XOR_WriteProcessMemory_0cb9 {
  strings:
    $key_0cb9 = { 5b cb [2] 69 e9 [2] 6f dc [2] 41 dc [2] 7e c0 }

  condition:
    any of them
}