rule TTP_XOR_WriteProcessMemory_1710 {
  strings:
    $key_1710 = { 40 62 [2] 72 40 [2] 74 75 [2] 5a 75 [2] 65 69 }

  condition:
    any of them
}