rule TTP_XOR_WriteProcessMemory_2c1e {
  strings:
    $key_2c1e = { 7b 6c [2] 49 4e [2] 4f 7b [2] 61 7b [2] 5e 67 }

  condition:
    any of them
}