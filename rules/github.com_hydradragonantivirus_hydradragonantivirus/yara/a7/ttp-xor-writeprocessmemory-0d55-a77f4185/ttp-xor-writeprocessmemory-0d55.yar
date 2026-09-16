rule TTP_XOR_WriteProcessMemory_0d55 {
  strings:
    $key_0d55 = { 5a 27 [2] 68 05 [2] 6e 30 [2] 40 30 [2] 7f 2c }

  condition:
    any of them
}