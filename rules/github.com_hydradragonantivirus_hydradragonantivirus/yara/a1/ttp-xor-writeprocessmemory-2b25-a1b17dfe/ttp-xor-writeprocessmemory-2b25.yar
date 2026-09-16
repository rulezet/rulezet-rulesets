rule TTP_XOR_WriteProcessMemory_2b25 {
  strings:
    $key_2b25 = { 7c 57 [2] 4e 75 [2] 48 40 [2] 66 40 [2] 59 5c }

  condition:
    any of them
}