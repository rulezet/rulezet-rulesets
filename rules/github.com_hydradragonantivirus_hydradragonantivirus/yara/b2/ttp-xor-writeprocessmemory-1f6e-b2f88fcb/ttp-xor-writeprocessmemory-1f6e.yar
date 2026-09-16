rule TTP_XOR_WriteProcessMemory_1f6e {
  strings:
    $key_1f6e = { 48 1c [2] 7a 3e [2] 7c 0b [2] 52 0b [2] 6d 17 }

  condition:
    any of them
}