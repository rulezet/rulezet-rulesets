rule TTP_XOR_WriteProcessMemory_1f55 {
  strings:
    $key_1f55 = { 48 27 [2] 7a 05 [2] 7c 30 [2] 52 30 [2] 6d 2c }

  condition:
    any of them
}