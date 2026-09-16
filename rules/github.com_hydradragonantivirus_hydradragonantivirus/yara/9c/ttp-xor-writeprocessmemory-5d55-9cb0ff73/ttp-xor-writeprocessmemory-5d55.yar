rule TTP_XOR_WriteProcessMemory_5d55 {
  strings:
    $key_5d55 = { 0a 27 [2] 38 05 [2] 3e 30 [2] 10 30 [2] 2f 2c }

  condition:
    any of them
}