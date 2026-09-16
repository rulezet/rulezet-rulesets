rule TTP_XOR_WriteProcessMemory_3905 {
  strings:
    $key_3905 = { 6e 77 [2] 5c 55 [2] 5a 60 [2] 74 60 [2] 4b 7c }

  condition:
    any of them
}