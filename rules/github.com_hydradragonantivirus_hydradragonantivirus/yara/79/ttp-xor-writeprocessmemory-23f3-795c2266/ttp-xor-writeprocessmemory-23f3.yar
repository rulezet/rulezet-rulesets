rule TTP_XOR_WriteProcessMemory_23f3 {
  strings:
    $key_23f3 = { 74 81 [2] 46 a3 [2] 40 96 [2] 6e 96 [2] 51 8a }

  condition:
    any of them
}