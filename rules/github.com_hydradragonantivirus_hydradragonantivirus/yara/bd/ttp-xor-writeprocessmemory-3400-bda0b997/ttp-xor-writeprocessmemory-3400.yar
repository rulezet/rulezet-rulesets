rule TTP_XOR_WriteProcessMemory_3400 {
  strings:
    $key_3400 = { 63 72 [2] 51 50 [2] 57 65 [2] 79 65 [2] 46 79 }

  condition:
    any of them
}