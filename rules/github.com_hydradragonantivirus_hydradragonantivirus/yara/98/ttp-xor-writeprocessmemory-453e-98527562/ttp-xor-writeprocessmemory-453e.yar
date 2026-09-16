rule TTP_XOR_WriteProcessMemory_453e {
  strings:
    $key_453e = { 12 4c [2] 20 6e [2] 26 5b [2] 08 5b [2] 37 47 }

  condition:
    any of them
}