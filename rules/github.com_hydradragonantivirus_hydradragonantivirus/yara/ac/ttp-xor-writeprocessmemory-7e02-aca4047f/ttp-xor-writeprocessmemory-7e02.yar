rule TTP_XOR_WriteProcessMemory_7e02 {
  strings:
    $key_7e02 = { 29 70 [2] 1b 52 [2] 1d 67 [2] 33 67 [2] 0c 7b }

  condition:
    any of them
}