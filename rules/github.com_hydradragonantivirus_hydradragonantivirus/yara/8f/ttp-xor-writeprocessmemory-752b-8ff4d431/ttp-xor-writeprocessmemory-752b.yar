rule TTP_XOR_WriteProcessMemory_752b {
  strings:
    $key_752b = { 22 59 [2] 10 7b [2] 16 4e [2] 38 4e [2] 07 52 }

  condition:
    any of them
}