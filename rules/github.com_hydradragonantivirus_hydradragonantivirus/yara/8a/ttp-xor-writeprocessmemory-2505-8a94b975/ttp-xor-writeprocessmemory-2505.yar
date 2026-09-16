rule TTP_XOR_WriteProcessMemory_2505 {
  strings:
    $key_2505 = { 72 77 [2] 40 55 [2] 46 60 [2] 68 60 [2] 57 7c }

  condition:
    any of them
}