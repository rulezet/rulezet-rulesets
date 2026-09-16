rule TTP_XOR_WriteProcessMemory_4905 {
  strings:
    $key_4905 = { 1e 77 [2] 2c 55 [2] 2a 60 [2] 04 60 [2] 3b 7c }

  condition:
    any of them
}