rule TTP_XOR_WriteProcessMemory_2b75 {
  strings:
    $key_2b75 = { 7c 07 [2] 4e 25 [2] 48 10 [2] 66 10 [2] 59 0c }

  condition:
    any of them
}