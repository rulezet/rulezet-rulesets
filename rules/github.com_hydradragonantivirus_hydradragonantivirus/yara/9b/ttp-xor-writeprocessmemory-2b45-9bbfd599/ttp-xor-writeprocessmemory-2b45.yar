rule TTP_XOR_WriteProcessMemory_2b45 {
  strings:
    $key_2b45 = { 7c 37 [2] 4e 15 [2] 48 20 [2] 66 20 [2] 59 3c }

  condition:
    any of them
}