rule TTP_XOR_WriteProcessMemory_2472 {
  strings:
    $key_2472 = { 73 00 [2] 41 22 [2] 47 17 [2] 69 17 [2] 56 0b }

  condition:
    any of them
}