rule TTP_XOR_WriteProcessMemory_0b3e {
  strings:
    $key_0b3e = { 5c 4c [2] 6e 6e [2] 68 5b [2] 46 5b [2] 79 47 }

  condition:
    any of them
}