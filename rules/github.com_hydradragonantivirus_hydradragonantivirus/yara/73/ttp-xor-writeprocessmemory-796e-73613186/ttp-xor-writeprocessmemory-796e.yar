rule TTP_XOR_WriteProcessMemory_796e {
  strings:
    $key_796e = { 2e 1c [2] 1c 3e [2] 1a 0b [2] 34 0b [2] 0b 17 }

  condition:
    any of them
}