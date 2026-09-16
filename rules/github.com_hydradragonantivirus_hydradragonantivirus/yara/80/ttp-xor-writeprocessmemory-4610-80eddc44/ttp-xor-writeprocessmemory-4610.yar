rule TTP_XOR_WriteProcessMemory_4610 {
  strings:
    $key_4610 = { 11 62 [2] 23 40 [2] 25 75 [2] 0b 75 [2] 34 69 }

  condition:
    any of them
}