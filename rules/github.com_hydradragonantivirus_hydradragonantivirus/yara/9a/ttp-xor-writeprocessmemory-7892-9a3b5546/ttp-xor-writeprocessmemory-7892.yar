rule TTP_XOR_WriteProcessMemory_7892 {
  strings:
    $key_7892 = { 2f e0 [2] 1d c2 [2] 1b f7 [2] 35 f7 [2] 0a eb }

  condition:
    any of them
}