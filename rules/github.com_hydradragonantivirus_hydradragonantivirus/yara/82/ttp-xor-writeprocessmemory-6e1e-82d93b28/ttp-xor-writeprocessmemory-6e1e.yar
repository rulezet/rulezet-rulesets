rule TTP_XOR_WriteProcessMemory_6e1e {
  strings:
    $key_6e1e = { 39 6c [2] 0b 4e [2] 0d 7b [2] 23 7b [2] 1c 67 }

  condition:
    any of them
}