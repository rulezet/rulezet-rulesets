rule TTP_XOR_WriteProcessMemory_0760 {
  strings:
    $key_0760 = { 50 12 [2] 62 30 [2] 64 05 [2] 4a 05 [2] 75 19 }

  condition:
    any of them
}