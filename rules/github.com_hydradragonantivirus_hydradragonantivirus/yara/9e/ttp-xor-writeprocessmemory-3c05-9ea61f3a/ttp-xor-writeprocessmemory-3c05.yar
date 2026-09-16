rule TTP_XOR_WriteProcessMemory_3c05 {
  strings:
    $key_3c05 = { 6b 77 [2] 59 55 [2] 5f 60 [2] 71 60 [2] 4e 7c }

  condition:
    any of them
}