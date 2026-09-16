rule TTP_XOR_WriteProcessMemory_6f6e {
  strings:
    $key_6f6e = { 38 1c [2] 0a 3e [2] 0c 0b [2] 22 0b [2] 1d 17 }

  condition:
    any of them
}