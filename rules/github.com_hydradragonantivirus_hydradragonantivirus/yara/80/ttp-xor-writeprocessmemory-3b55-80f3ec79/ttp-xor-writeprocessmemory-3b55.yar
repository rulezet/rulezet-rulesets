rule TTP_XOR_WriteProcessMemory_3b55 {
  strings:
    $key_3b55 = { 6c 27 [2] 5e 05 [2] 58 30 [2] 76 30 [2] 49 2c }

  condition:
    any of them
}