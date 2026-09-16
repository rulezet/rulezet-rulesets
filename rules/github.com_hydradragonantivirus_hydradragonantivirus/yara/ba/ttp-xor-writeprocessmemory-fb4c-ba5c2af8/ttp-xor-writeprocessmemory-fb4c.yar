rule TTP_XOR_WriteProcessMemory_fb4c {
  strings:
    $key_fb4c = { ac 3e [2] 9e 1c [2] 98 29 [2] b6 29 [2] 89 35 }

  condition:
    any of them
}