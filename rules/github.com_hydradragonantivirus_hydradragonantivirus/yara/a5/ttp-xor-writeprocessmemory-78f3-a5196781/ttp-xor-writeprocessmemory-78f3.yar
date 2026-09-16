rule TTP_XOR_WriteProcessMemory_78f3 {
  strings:
    $key_78f3 = { 2f 81 [2] 1d a3 [2] 1b 96 [2] 35 96 [2] 0a 8a }

  condition:
    any of them
}