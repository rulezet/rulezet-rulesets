rule TTP_XOR_WriteProcessMemory_3c6e {
  strings:
    $key_3c6e = { 6b 1c [2] 59 3e [2] 5f 0b [2] 71 0b [2] 4e 17 }

  condition:
    any of them
}