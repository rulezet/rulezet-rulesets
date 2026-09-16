rule TTP_XOR_WriteProcessMemory_3410 {
  strings:
    $key_3410 = { 63 62 [2] 51 40 [2] 57 75 [2] 79 75 [2] 46 69 }

  condition:
    any of them
}