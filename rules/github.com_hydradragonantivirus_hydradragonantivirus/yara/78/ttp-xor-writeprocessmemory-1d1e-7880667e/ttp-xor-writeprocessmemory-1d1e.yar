rule TTP_XOR_WriteProcessMemory_1d1e {
  strings:
    $key_1d1e = { 4a 6c [2] 78 4e [2] 7e 7b [2] 50 7b [2] 6f 67 }

  condition:
    any of them
}