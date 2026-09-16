rule TTP_XOR_WriteProcessMemory_0b55 {
  strings:
    $key_0b55 = { 5c 27 [2] 6e 05 [2] 68 30 [2] 46 30 [2] 79 2c }

  condition:
    any of them
}