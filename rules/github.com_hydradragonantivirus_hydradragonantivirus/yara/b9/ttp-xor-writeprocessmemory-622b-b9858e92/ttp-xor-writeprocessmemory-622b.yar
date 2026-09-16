rule TTP_XOR_WriteProcessMemory_622b {
  strings:
    $key_622b = { 35 59 [2] 07 7b [2] 01 4e [2] 2f 4e [2] 10 52 }

  condition:
    any of them
}