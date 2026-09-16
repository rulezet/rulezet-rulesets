rule TTP_XOR_WriteProcessMemory_1205 {
  strings:
    $key_1205 = { 45 77 [2] 77 55 [2] 71 60 [2] 5f 60 [2] 60 7c }

  condition:
    any of them
}