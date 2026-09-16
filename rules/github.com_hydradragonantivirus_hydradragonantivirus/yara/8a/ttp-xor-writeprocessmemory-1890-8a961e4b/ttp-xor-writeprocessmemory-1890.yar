rule TTP_XOR_WriteProcessMemory_1890 {
  strings:
    $key_1890 = { 4f e2 [2] 7d c0 [2] 7b f5 [2] 55 f5 [2] 6a e9 }

  condition:
    any of them
}