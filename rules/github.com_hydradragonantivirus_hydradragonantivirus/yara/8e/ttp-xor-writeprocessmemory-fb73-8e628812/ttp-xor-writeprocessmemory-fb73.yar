rule TTP_XOR_WriteProcessMemory_fb73 {
  strings:
    $key_fb73 = { ac 01 [2] 9e 23 [2] 98 16 [2] b6 16 [2] 89 0a }

  condition:
    any of them
}