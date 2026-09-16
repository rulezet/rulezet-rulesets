rule TTP_XOR_WriteProcessMemory_56e5 {
  strings:
    $key_56e5 = { 01 97 [2] 33 b5 [2] 35 80 [2] 1b 80 [2] 24 9c }

  condition:
    any of them
}