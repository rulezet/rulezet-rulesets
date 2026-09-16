rule TTP_XOR_WriteProcessMemory_6775 {
  strings:
    $key_6775 = { 30 07 [2] 02 25 [2] 04 10 [2] 2a 10 [2] 15 0c }

  condition:
    any of them
}