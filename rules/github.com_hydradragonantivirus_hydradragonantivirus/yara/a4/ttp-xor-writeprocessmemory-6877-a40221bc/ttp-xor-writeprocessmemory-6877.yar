rule TTP_XOR_WriteProcessMemory_6877 {
  strings:
    $key_6877 = { 3f 05 [2] 0d 27 [2] 0b 12 [2] 25 12 [2] 1a 0e }

  condition:
    any of them
}