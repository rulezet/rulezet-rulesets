rule TTP_XOR_WriteProcessMemory_2540 {
  strings:
    $key_2540 = { 72 32 [2] 40 10 [2] 46 25 [2] 68 25 [2] 57 39 }

  condition:
    any of them
}