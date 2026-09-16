rule TTP_XOR_WriteProcessMemory_fe4e {
  strings:
    $key_fe4e = { a9 3c [2] 9b 1e [2] 9d 2b [2] b3 2b [2] 8c 37 }

  condition:
    any of them
}