rule TTP_XOR_WriteProcessMemory_5105 {
  strings:
    $key_5105 = { 06 77 [2] 34 55 [2] 32 60 [2] 1c 60 [2] 23 7c }

  condition:
    any of them
}