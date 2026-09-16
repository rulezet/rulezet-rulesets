rule TTP_XOR_WriteProcessMemory_4890 {
  strings:
    $key_4890 = { 1f e2 [2] 2d c0 [2] 2b f5 [2] 05 f5 [2] 3a e9 }

  condition:
    any of them
}