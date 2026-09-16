rule TTP_XOR_WriteProcessMemory_1b05 {
  strings:
    $key_1b05 = { 4c 77 [2] 7e 55 [2] 78 60 [2] 56 60 [2] 69 7c }

  condition:
    any of them
}