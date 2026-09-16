rule TTP_XOR_WriteProcessMemory_2175 {
  strings:
    $key_2175 = { 76 07 [2] 44 25 [2] 42 10 [2] 6c 10 [2] 53 0c }

  condition:
    any of them
}