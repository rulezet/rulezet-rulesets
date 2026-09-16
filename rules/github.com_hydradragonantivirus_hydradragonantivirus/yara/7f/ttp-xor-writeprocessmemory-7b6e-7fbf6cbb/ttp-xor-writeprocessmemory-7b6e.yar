rule TTP_XOR_WriteProcessMemory_7b6e {
  strings:
    $key_7b6e = { 2c 1c [2] 1e 3e [2] 18 0b [2] 36 0b [2] 09 17 }

  condition:
    any of them
}