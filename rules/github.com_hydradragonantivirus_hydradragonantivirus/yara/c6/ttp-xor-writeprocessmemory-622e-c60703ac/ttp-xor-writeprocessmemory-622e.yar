rule TTP_XOR_WriteProcessMemory_622e {
  strings:
    $key_622e = { 35 5c [2] 07 7e [2] 01 4b [2] 2f 4b [2] 10 57 }

  condition:
    any of them
}