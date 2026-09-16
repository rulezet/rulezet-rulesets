rule TTP_XOR_WriteProcessMemory_fbb9 {
  strings:
    $key_fbb9 = { ac cb [2] 9e e9 [2] 98 dc [2] b6 dc [2] 89 c0 }

  condition:
    any of them
}