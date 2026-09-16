rule TTP_XOR_WriteProcessMemory_0b05 {
  strings:
    $key_0b05 = { 5c 77 [2] 6e 55 [2] 68 60 [2] 46 60 [2] 79 7c }

  condition:
    any of them
}