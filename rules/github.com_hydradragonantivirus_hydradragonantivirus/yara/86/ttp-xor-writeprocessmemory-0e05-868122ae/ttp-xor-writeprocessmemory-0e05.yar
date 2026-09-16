rule TTP_XOR_WriteProcessMemory_0e05 {
  strings:
    $key_0e05 = { 59 77 [2] 6b 55 [2] 6d 60 [2] 43 60 [2] 7c 7c }

  condition:
    any of them
}