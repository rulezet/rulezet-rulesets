rule TTP_XOR_WriteProcessMemory_531e {
  strings:
    $key_531e = { 04 6c [2] 36 4e [2] 30 7b [2] 1e 7b [2] 21 67 }

  condition:
    any of them
}