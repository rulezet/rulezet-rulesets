rule TTP_XOR_WriteProcessMemory_fe7e {
  strings:
    $key_fe7e = { a9 0c [2] 9b 2e [2] 9d 1b [2] b3 1b [2] 8c 07 }

  condition:
    any of them
}