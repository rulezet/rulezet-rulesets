rule TTP_XOR_WriteProcessMemory_fb2c {
  strings:
    $key_fb2c = { ac 5e [2] 9e 7c [2] 98 49 [2] b6 49 [2] 89 55 }

  condition:
    any of them
}