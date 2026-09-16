rule TTP_XOR_WriteProcessMemory_7e55 {
  strings:
    $key_7e55 = { 29 27 [2] 1b 05 [2] 1d 30 [2] 33 30 [2] 0c 2c }

  condition:
    any of them
}