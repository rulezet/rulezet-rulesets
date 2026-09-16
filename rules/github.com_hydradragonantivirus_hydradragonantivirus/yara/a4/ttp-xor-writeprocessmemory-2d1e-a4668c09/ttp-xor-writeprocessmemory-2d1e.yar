rule TTP_XOR_WriteProcessMemory_2d1e {
  strings:
    $key_2d1e = { 7a 6c [2] 48 4e [2] 4e 7b [2] 60 7b [2] 5f 67 }

  condition:
    any of them
}