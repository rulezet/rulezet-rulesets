rule TTP_XOR_WriteProcessMemory_7815 {
  strings:
    $key_7815 = { 2f 67 [2] 1d 45 [2] 1b 70 [2] 35 70 [2] 0a 6c }

  condition:
    any of them
}