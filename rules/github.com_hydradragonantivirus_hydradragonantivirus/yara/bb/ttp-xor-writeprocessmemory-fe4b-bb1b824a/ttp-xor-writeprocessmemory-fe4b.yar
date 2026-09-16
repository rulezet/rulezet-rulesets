rule TTP_XOR_WriteProcessMemory_fe4b {
  strings:
    $key_fe4b = { a9 39 [2] 9b 1b [2] 9d 2e [2] b3 2e [2] 8c 32 }

  condition:
    any of them
}