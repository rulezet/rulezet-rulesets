rule TTP_XOR_WriteProcessMemory_0f05 {
  strings:
    $key_0f05 = { 58 77 [2] 6a 55 [2] 6c 60 [2] 42 60 [2] 7d 7c }

  condition:
    any of them
}