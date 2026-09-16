rule TTP_XOR_WriteProcessMemory_2400 {
  strings:
    $key_2400 = { 73 72 [2] 41 50 [2] 47 65 [2] 69 65 [2] 56 79 }

  condition:
    any of them
}