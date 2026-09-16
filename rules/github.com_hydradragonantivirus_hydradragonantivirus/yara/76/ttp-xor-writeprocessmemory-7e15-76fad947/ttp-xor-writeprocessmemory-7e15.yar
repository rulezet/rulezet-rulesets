rule TTP_XOR_WriteProcessMemory_7e15 {
  strings:
    $key_7e15 = { 29 67 [2] 1b 45 [2] 1d 70 [2] 33 70 [2] 0c 6c }

  condition:
    any of them
}