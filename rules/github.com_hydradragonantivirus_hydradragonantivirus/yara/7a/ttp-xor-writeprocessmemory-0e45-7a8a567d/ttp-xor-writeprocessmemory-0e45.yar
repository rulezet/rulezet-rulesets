rule TTP_XOR_WriteProcessMemory_0e45 {
  strings:
    $key_0e45 = { 59 37 [2] 6b 15 [2] 6d 20 [2] 43 20 [2] 7c 3c }

  condition:
    any of them
}