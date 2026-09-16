rule TTP_XOR_WriteProcessMemory_4c75 {
  strings:
    $key_4c75 = { 1b 07 [2] 29 25 [2] 2f 10 [2] 01 10 [2] 3e 0c }

  condition:
    any of them
}