rule TTP_XOR_WriteProcessMemory_fb0b {
  strings:
    $key_fb0b = { ac 79 [2] 9e 5b [2] 98 6e [2] b6 6e [2] 89 72 }

  condition:
    any of them
}