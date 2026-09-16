rule TTP_XOR_WriteProcessMemory_1110 {
  strings:
    $key_1110 = { 46 62 [2] 74 40 [2] 72 75 [2] 5c 75 [2] 63 69 }

  condition:
    any of them
}