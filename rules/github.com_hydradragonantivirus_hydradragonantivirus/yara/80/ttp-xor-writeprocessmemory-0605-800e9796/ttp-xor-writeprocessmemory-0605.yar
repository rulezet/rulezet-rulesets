rule TTP_XOR_WriteProcessMemory_0605 {
  strings:
    $key_0605 = { 51 77 [2] 63 55 [2] 65 60 [2] 4b 60 [2] 74 7c }

  condition:
    any of them
}