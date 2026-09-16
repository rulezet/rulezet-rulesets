rule TTP_XOR_WriteProcessMemory_3f05 {
  strings:
    $key_3f05 = { 68 77 [2] 5a 55 [2] 5c 60 [2] 72 60 [2] 4d 7c }

  condition:
    any of them
}