rule TTP_XOR_WriteProcessMemory_6405 {
  strings:
    $key_6405 = { 33 77 [2] 01 55 [2] 07 60 [2] 29 60 [2] 16 7c }

  condition:
    any of them
}