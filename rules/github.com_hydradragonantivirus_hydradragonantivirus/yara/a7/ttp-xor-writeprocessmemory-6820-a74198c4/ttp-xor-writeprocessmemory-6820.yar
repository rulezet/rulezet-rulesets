rule TTP_XOR_WriteProcessMemory_6820 {
  strings:
    $key_6820 = { 3f 52 [2] 0d 70 [2] 0b 45 [2] 25 45 [2] 1a 59 }

  condition:
    any of them
}