rule TTP_XOR_WriteProcessMemory_6d15 {
  strings:
    $key_6d15 = { 3a 67 [2] 08 45 [2] 0e 70 [2] 20 70 [2] 1f 6c }

  condition:
    any of them
}