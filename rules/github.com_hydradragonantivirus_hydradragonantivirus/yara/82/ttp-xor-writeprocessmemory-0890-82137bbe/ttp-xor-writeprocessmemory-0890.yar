rule TTP_XOR_WriteProcessMemory_0890 {
  strings:
    $key_0890 = { 5f e2 [2] 6d c0 [2] 6b f5 [2] 45 f5 [2] 7a e9 }

  condition:
    any of them
}