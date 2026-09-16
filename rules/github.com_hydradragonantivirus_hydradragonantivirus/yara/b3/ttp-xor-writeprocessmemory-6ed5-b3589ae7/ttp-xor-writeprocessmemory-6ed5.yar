rule TTP_XOR_WriteProcessMemory_6ed5 {
  strings:
    $key_6ed5 = { 39 a7 [2] 0b 85 [2] 0d b0 [2] 23 b0 [2] 1c ac }

  condition:
    any of them
}