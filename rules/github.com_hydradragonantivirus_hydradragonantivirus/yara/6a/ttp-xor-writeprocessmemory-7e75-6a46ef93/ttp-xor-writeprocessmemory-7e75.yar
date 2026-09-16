rule TTP_XOR_WriteProcessMemory_7e75 {
  strings:
    $key_7e75 = { 29 07 [2] 1b 25 [2] 1d 10 [2] 33 10 [2] 0c 0c }

  condition:
    any of them
}