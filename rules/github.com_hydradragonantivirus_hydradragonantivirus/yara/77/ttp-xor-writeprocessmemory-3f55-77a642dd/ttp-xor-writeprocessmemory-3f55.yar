rule TTP_XOR_WriteProcessMemory_3f55 {
  strings:
    $key_3f55 = { 68 27 [2] 5a 05 [2] 5c 30 [2] 72 30 [2] 4d 2c }

  condition:
    any of them
}