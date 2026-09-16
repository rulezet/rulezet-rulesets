rule TTP_XOR_WriteProcessMemory_2dfb {
  strings:
    $key_2dfb = { 7a 89 [2] 48 ab [2] 4e 9e [2] 60 9e [2] 5f 82 }

  condition:
    any of them
}