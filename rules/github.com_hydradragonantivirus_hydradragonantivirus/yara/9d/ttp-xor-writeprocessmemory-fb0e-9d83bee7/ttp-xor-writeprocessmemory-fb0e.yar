rule TTP_XOR_WriteProcessMemory_fb0e {
  strings:
    $key_fb0e = { ac 7c [2] 9e 5e [2] 98 6b [2] b6 6b [2] 89 77 }

  condition:
    any of them
}