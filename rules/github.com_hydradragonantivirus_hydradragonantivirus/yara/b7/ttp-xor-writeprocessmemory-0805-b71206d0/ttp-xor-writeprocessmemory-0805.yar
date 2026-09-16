rule TTP_XOR_WriteProcessMemory_0805 {
  strings:
    $key_0805 = { 5f 77 [2] 6d 55 [2] 6b 60 [2] 45 60 [2] 7a 7c }

  condition:
    any of them
}