rule TTP_XOR_WriteProcessMemory_55f3 {
  strings:
    $key_55f3 = { 02 81 [2] 30 a3 [2] 36 96 [2] 18 96 [2] 27 8a }

  condition:
    any of them
}