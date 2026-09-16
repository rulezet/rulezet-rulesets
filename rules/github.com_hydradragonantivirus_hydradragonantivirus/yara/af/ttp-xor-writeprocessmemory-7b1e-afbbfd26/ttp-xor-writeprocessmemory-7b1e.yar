rule TTP_XOR_WriteProcessMemory_7b1e {
  strings:
    $key_7b1e = { 2c 6c [2] 1e 4e [2] 18 7b [2] 36 7b [2] 09 67 }

  condition:
    any of them
}