rule TTP_XOR_WriteProcessMemory_56f2 {
  strings:
    $key_56f2 = { 01 80 [2] 33 a2 [2] 35 97 [2] 1b 97 [2] 24 8b }

  condition:
    any of them
}