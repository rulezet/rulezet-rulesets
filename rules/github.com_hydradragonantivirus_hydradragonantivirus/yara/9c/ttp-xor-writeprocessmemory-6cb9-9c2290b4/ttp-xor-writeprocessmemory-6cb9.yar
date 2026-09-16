rule TTP_XOR_WriteProcessMemory_6cb9 {
  strings:
    $key_6cb9 = { 3b cb [2] 09 e9 [2] 0f dc [2] 21 dc [2] 1e c0 }

  condition:
    any of them
}