rule TTP_XOR_WriteProcessMemory_3e05 {
  strings:
    $key_3e05 = { 69 77 [2] 5b 55 [2] 5d 60 [2] 73 60 [2] 4c 7c }

  condition:
    any of them
}