rule TTP_XOR_WriteProcessMemory_6d55 {
  strings:
    $key_6d55 = { 3a 27 [2] 08 05 [2] 0e 30 [2] 20 30 [2] 1f 2c }

  condition:
    any of them
}