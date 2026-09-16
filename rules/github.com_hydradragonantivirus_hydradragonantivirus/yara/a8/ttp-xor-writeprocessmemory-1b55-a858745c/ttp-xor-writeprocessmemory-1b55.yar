rule TTP_XOR_WriteProcessMemory_1b55 {
  strings:
    $key_1b55 = { 4c 27 [2] 7e 05 [2] 78 30 [2] 56 30 [2] 69 2c }

  condition:
    any of them
}