rule TTP_XOR_WriteProcessMemory_2b05 {
  strings:
    $key_2b05 = { 7c 77 [2] 4e 55 [2] 48 60 [2] 66 60 [2] 59 7c }

  condition:
    any of them
}