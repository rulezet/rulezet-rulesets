rule TTP_XOR_WriteProcessMemory_fb72 {
  strings:
    $key_fb72 = { ac 00 [2] 9e 22 [2] 98 17 [2] b6 17 [2] 89 0b }

  condition:
    any of them
}