rule TTP_XOR_WriteProcessMemory_fb50 {
  strings:
    $key_fb50 = { ac 22 [2] 9e 00 [2] 98 35 [2] b6 35 [2] 89 29 }

  condition:
    any of them
}