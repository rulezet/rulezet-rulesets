rule TTP_XOR_WriteProcessMemory_fb65 {
  strings:
    $key_fb65 = { ac 17 [2] 9e 35 [2] 98 00 [2] b6 00 [2] 89 1c }

  condition:
    any of them
}