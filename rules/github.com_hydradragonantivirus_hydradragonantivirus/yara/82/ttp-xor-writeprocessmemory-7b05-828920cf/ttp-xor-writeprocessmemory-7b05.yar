rule TTP_XOR_WriteProcessMemory_7b05 {
  strings:
    $key_7b05 = { 2c 77 [2] 1e 55 [2] 18 60 [2] 36 60 [2] 09 7c }

  condition:
    any of them
}