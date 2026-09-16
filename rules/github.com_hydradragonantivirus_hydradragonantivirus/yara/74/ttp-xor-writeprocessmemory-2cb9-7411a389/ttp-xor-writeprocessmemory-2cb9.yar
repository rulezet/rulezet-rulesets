rule TTP_XOR_WriteProcessMemory_2cb9 {
  strings:
    $key_2cb9 = { 7b cb [2] 49 e9 [2] 4f dc [2] 61 dc [2] 5e c0 }

  condition:
    any of them
}