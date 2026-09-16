rule TTP_XOR_WriteProcessMemory_fb4e {
  strings:
    $key_fb4e = { ac 3c [2] 9e 1e [2] 98 2b [2] b6 2b [2] 89 37 }

  condition:
    any of them
}