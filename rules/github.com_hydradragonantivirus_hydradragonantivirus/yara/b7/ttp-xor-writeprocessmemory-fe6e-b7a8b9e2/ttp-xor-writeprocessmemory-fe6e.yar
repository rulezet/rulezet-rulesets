rule TTP_XOR_WriteProcessMemory_fe6e {
  strings:
    $key_fe6e = { a9 1c [2] 9b 3e [2] 9d 0b [2] b3 0b [2] 8c 17 }

  condition:
    any of them
}