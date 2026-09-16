rule TTP_XOR_WriteProcessMemory_4601 {
  strings:
    $key_4601 = { 11 73 [2] 23 51 [2] 25 64 [2] 0b 64 [2] 34 78 }

  condition:
    any of them
}