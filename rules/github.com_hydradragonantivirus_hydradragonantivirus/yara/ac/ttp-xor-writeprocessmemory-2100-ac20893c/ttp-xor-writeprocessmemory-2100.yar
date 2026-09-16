rule TTP_XOR_WriteProcessMemory_2100 {
  strings:
    $key_2100 = { 76 72 [2] 44 50 [2] 42 65 [2] 6c 65 [2] 53 79 }

  condition:
    any of them
}