rule TTP_XOR_WriteProcessMemory_2e05 {
  strings:
    $key_2e05 = { 79 77 [2] 4b 55 [2] 4d 60 [2] 63 60 [2] 5c 7c }

  condition:
    any of them
}