rule TTP_XOR_WriteProcessMemory_1c05 {
  strings:
    $key_1c05 = { 4b 77 [2] 79 55 [2] 7f 60 [2] 51 60 [2] 6e 7c }

  condition:
    any of them
}