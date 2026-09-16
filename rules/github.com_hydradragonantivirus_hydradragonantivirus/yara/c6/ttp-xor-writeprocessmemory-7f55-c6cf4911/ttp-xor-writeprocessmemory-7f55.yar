rule TTP_XOR_WriteProcessMemory_7f55 {
  strings:
    $key_7f55 = { 28 27 [2] 1a 05 [2] 1c 30 [2] 32 30 [2] 0d 2c }

  condition:
    any of them
}