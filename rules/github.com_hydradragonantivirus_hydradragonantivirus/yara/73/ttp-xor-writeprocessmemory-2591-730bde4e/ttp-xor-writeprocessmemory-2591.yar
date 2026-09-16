rule TTP_XOR_WriteProcessMemory_2591 {
  strings:
    $key_2591 = { 72 e3 [2] 40 c1 [2] 46 f4 [2] 68 f4 [2] 57 e8 }

  condition:
    any of them
}