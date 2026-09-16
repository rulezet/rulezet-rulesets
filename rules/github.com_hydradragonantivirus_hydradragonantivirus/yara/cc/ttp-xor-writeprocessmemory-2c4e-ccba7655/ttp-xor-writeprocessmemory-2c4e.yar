rule TTP_XOR_WriteProcessMemory_2c4e {
  strings:
    $key_2c4e = { 7b 3c [2] 49 1e [2] 4f 2b [2] 61 2b [2] 5e 37 }

  condition:
    any of them
}