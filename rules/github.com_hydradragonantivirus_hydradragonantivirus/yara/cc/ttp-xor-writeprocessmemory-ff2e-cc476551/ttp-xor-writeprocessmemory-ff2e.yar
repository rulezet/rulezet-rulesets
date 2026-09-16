rule TTP_XOR_WriteProcessMemory_ff2e {
  strings:
    $key_ff2e = { a8 5c [2] 9a 7e [2] 9c 4b [2] b2 4b [2] 8d 57 }

  condition:
    any of them
}