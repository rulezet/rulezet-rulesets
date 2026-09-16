rule TTP_XOR_WriteProcessMemory_ff5c {
  strings:
    $key_ff5c = { a8 2e [2] 9a 0c [2] 9c 39 [2] b2 39 [2] 8d 25 }

  condition:
    any of them
}