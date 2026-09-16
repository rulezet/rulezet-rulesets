rule TTP_XOR_WriteProcessMemory_6e3e {
  strings:
    $key_6e3e = { 39 4c [2] 0b 6e [2] 0d 5b [2] 23 5b [2] 1c 47 }

  condition:
    any of them
}