rule TTP_XOR_WriteProcessMemory_4c05 {
  strings:
    $key_4c05 = { 1b 77 [2] 29 55 [2] 2f 60 [2] 01 60 [2] 3e 7c }

  condition:
    any of them
}