rule TTP_XOR_WriteProcessMemory_0731 {
  strings:
    $key_0731 = { 50 43 [2] 62 61 [2] 64 54 [2] 4a 54 [2] 75 48 }

  condition:
    any of them
}