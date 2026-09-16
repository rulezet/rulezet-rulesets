rule TTP_XOR_WriteProcessMemory_4775 {
  strings:
    $key_4775 = { 10 07 [2] 22 25 [2] 24 10 [2] 0a 10 [2] 35 0c }

  condition:
    any of them
}