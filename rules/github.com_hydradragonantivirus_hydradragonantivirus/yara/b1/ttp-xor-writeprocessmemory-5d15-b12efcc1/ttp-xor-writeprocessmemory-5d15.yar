rule TTP_XOR_WriteProcessMemory_5d15 {
  strings:
    $key_5d15 = { 0a 67 [2] 38 45 [2] 3e 70 [2] 10 70 [2] 2f 6c }

  condition:
    any of them
}