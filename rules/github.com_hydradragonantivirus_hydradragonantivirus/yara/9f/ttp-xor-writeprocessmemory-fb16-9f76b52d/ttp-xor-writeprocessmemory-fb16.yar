rule TTP_XOR_WriteProcessMemory_fb16 {
  strings:
    $key_fb16 = { ac 64 [2] 9e 46 [2] 98 73 [2] b6 73 [2] 89 6f }

  condition:
    any of them
}