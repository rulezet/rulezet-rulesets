rule TTP_XOR_WriteProcessMemory_4710 {
  strings:
    $key_4710 = { 10 62 [2] 22 40 [2] 24 75 [2] 0a 75 [2] 35 69 }

  condition:
    any of them
}