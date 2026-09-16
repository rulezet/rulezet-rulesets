rule TTP_XOR_WriteProcessMemory_6f25 {
  strings:
    $key_6f25 = { 38 57 [2] 0a 75 [2] 0c 40 [2] 22 40 [2] 1d 5c }

  condition:
    any of them
}