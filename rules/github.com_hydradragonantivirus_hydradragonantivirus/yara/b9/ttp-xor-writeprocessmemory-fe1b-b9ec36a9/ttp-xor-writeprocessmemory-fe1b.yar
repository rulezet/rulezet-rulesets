rule TTP_XOR_WriteProcessMemory_fe1b {
  strings:
    $key_fe1b = { a9 69 [2] 9b 4b [2] 9d 7e [2] b3 7e [2] 8c 62 }

  condition:
    any of them
}