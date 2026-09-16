rule TTP_XOR_WriteProcessMemory_1364 {
  strings:
    $key_1364 = { 44 16 [2] 76 34 [2] 70 01 [2] 5e 01 [2] 61 1d }

  condition:
    any of them
}