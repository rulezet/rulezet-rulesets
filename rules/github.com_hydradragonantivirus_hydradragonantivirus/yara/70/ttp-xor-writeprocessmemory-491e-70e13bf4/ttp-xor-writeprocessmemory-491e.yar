rule TTP_XOR_WriteProcessMemory_491e {
  strings:
    $key_491e = { 1e 6c [2] 2c 4e [2] 2a 7b [2] 04 7b [2] 3b 67 }

  condition:
    any of them
}