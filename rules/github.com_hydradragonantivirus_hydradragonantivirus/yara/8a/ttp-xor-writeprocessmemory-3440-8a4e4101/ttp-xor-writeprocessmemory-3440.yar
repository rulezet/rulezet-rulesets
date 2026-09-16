rule TTP_XOR_WriteProcessMemory_3440 {
  strings:
    $key_3440 = { 63 32 [2] 51 10 [2] 57 25 [2] 79 25 [2] 46 39 }

  condition:
    any of them
}