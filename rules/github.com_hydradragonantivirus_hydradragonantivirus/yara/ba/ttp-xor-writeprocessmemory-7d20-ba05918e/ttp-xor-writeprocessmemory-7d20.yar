rule TTP_XOR_WriteProcessMemory_7d20 {
  strings:
    $key_7d20 = { 2a 52 [2] 18 70 [2] 1e 45 [2] 30 45 [2] 0f 59 }

  condition:
    any of them
}