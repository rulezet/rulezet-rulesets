rule TTP_XOR_WriteProcessMemory_4892 {
  strings:
    $key_4892 = { 1f e0 [2] 2d c2 [2] 2b f7 [2] 05 f7 [2] 3a eb }

  condition:
    any of them
}