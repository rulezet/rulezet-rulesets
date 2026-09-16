rule TTP_XOR_WriteProcessMemory_0b6e {
  strings:
    $key_0b6e = { 5c 1c [2] 6e 3e [2] 68 0b [2] 46 0b [2] 79 17 }

  condition:
    any of them
}