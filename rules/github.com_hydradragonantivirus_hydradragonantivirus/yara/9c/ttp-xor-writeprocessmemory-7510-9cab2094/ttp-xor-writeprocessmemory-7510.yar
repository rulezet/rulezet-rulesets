rule TTP_XOR_WriteProcessMemory_7510 {
  strings:
    $key_7510 = { 22 62 [2] 10 40 [2] 16 75 [2] 38 75 [2] 07 69 }

  condition:
    any of them
}