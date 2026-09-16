rule TTP_XOR_WriteProcessMemory_3605 {
  strings:
    $key_3605 = { 61 77 [2] 53 55 [2] 55 60 [2] 7b 60 [2] 44 7c }

  condition:
    any of them
}