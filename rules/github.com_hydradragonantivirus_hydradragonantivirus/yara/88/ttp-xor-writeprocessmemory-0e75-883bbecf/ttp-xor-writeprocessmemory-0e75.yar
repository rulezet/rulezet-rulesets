rule TTP_XOR_WriteProcessMemory_0e75 {
  strings:
    $key_0e75 = { 59 07 [2] 6b 25 [2] 6d 10 [2] 43 10 [2] 7c 0c }

  condition:
    any of them
}