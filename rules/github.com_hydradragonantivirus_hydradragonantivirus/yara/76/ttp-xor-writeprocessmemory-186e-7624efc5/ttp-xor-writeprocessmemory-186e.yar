rule TTP_XOR_WriteProcessMemory_186e {
  strings:
    $key_186e = { 4f 1c [2] 7d 3e [2] 7b 0b [2] 55 0b [2] 6a 17 }

  condition:
    any of them
}