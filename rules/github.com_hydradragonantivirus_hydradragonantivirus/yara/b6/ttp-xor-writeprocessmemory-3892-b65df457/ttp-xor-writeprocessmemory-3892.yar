rule TTP_XOR_WriteProcessMemory_3892 {
  strings:
    $key_3892 = { 6f e0 [2] 5d c2 [2] 5b f7 [2] 75 f7 [2] 4a eb }

  condition:
    any of them
}