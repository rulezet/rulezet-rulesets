rule TTP_XOR_WriteProcessMemory_fb67 {
  strings:
    $key_fb67 = { ac 15 [2] 9e 37 [2] 98 02 [2] b6 02 [2] 89 1e }

  condition:
    any of them
}