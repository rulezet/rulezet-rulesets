rule TTP_XOR_WriteProcessMemory_fb5e {
  strings:
    $key_fb5e = { ac 2c [2] 9e 0e [2] 98 3b [2] b6 3b [2] 89 27 }

  condition:
    any of them
}