rule TTP_XOR_WriteProcessMemory_ff6e {
  strings:
    $key_ff6e = { a8 1c [2] 9a 3e [2] 9c 0b [2] b2 0b [2] 8d 17 }

  condition:
    any of them
}