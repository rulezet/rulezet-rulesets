rule TTP_XOR_WriteProcessMemory_2749 {
  strings:
    $key_2749 = { 70 3b [2] 42 19 [2] 44 2c [2] 6a 2c [2] 55 30 }

  condition:
    any of them
}