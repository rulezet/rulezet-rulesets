rule TTP_XOR_WriteProcessMemory_1d6e {
  strings:
    $key_1d6e = { 4a 1c [2] 78 3e [2] 7e 0b [2] 50 0b [2] 6f 17 }

  condition:
    any of them
}