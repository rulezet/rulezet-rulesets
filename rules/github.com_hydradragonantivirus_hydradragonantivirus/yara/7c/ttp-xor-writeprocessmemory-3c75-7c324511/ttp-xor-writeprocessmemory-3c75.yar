rule TTP_XOR_WriteProcessMemory_3c75 {
  strings:
    $key_3c75 = { 6b 07 [2] 59 25 [2] 5f 10 [2] 71 10 [2] 4e 0c }

  condition:
    any of them
}