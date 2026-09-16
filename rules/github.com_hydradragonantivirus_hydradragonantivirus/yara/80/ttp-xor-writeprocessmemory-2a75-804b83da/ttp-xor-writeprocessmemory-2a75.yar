rule TTP_XOR_WriteProcessMemory_2a75 {
  strings:
    $key_2a75 = { 7d 07 [2] 4f 25 [2] 49 10 [2] 67 10 [2] 58 0c }

  condition:
    any of them
}