rule TTP_XOR_WriteProcessMemory_3460 {
  strings:
    $key_3460 = { 63 12 [2] 51 30 [2] 57 05 [2] 79 05 [2] 46 19 }

  condition:
    any of them
}