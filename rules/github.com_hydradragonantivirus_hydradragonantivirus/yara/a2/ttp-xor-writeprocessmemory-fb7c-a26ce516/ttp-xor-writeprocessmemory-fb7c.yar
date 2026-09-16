rule TTP_XOR_WriteProcessMemory_fb7c {
  strings:
    $key_fb7c = { ac 0e [2] 9e 2c [2] 98 19 [2] b6 19 [2] 89 05 }

  condition:
    any of them
}