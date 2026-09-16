rule TTP_XOR_WriteProcessMemory_2155 {
  strings:
    $key_2155 = { 76 27 [2] 44 05 [2] 42 30 [2] 6c 30 [2] 53 2c }

  condition:
    any of them
}