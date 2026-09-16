rule TTP_XOR_WriteProcessMemory_fb6c {
  strings:
    $key_fb6c = { ac 1e [2] 9e 3c [2] 98 09 [2] b6 09 [2] 89 15 }

  condition:
    any of them
}