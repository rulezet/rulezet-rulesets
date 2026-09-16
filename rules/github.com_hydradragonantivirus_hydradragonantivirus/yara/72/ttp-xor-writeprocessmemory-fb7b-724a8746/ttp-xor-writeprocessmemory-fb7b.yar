rule TTP_XOR_WriteProcessMemory_fb7b {
  strings:
    $key_fb7b = { ac 09 [2] 9e 2b [2] 98 1e [2] b6 1e [2] 89 02 }

  condition:
    any of them
}