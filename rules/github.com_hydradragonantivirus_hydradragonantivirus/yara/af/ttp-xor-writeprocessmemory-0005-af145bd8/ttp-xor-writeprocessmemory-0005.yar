rule TTP_XOR_WriteProcessMemory_0005 {
  strings:
    $key_0005 = { 57 77 [2] 65 55 [2] 63 60 [2] 4d 60 [2] 72 7c }

  condition:
    any of them
}