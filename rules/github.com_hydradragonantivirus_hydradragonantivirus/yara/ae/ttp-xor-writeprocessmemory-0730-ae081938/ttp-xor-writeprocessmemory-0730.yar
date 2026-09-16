rule TTP_XOR_WriteProcessMemory_0730 {
  strings:
    $key_0730 = { 50 42 [2] 62 60 [2] 64 55 [2] 4a 55 [2] 75 49 }

  condition:
    any of them
}