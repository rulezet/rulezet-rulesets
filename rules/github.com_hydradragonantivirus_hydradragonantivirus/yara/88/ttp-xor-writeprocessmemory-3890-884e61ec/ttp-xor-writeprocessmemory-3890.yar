rule TTP_XOR_WriteProcessMemory_3890 {
  strings:
    $key_3890 = { 6f e2 [2] 5d c0 [2] 5b f5 [2] 75 f5 [2] 4a e9 }

  condition:
    any of them
}