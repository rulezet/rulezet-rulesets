rule TTP_XOR_WriteProcessMemory_45f3 {
  strings:
    $key_45f3 = { 12 81 [2] 20 a3 [2] 26 96 [2] 08 96 [2] 37 8a }

  condition:
    any of them
}