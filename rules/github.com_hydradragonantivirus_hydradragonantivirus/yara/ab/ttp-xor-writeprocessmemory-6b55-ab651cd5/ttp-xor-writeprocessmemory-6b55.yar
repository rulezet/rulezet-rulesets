rule TTP_XOR_WriteProcessMemory_6b55 {
  strings:
    $key_6b55 = { 3c 27 [2] 0e 05 [2] 08 30 [2] 26 30 [2] 19 2c }

  condition:
    any of them
}