rule TTP_XOR_WriteProcessMemory_0f55 {
  strings:
    $key_0f55 = { 58 27 [2] 6a 05 [2] 6c 30 [2] 42 30 [2] 7d 2c }

  condition:
    any of them
}