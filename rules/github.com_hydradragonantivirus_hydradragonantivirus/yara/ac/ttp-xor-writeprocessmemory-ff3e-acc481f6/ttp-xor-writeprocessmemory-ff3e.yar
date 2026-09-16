rule TTP_XOR_WriteProcessMemory_ff3e {
  strings:
    $key_ff3e = { a8 4c [2] 9a 6e [2] 9c 5b [2] b2 5b [2] 8d 47 }

  condition:
    any of them
}