rule TTP_XOR_WriteProcessMemory_c997 {
  strings:
    $key_c997 = { 9e e5 [2] ac c7 [2] aa f2 [2] 84 f2 [2] bb ee }

  condition:
    any of them
}