rule TTP_XOR_WriteProcessMemory_4d6e {
  strings:
    $key_4d6e = { 1a 1c [2] 28 3e [2] 2e 0b [2] 00 0b [2] 3f 17 }

  condition:
    any of them
}