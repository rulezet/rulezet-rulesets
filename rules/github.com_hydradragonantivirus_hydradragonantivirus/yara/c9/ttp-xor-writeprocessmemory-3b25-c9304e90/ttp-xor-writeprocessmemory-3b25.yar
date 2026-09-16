rule TTP_XOR_WriteProcessMemory_3b25 {
  strings:
    $key_3b25 = { 6c 57 [2] 5e 75 [2] 58 40 [2] 76 40 [2] 49 5c }

  condition:
    any of them
}