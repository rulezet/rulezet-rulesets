rule TTP_XOR_WriteProcessMemory_0892 {
  strings:
    $key_0892 = { 5f e0 [2] 6d c2 [2] 6b f7 [2] 45 f7 [2] 7a eb }

  condition:
    any of them
}