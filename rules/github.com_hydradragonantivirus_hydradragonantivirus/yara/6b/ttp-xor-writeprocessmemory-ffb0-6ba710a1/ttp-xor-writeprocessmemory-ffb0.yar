rule TTP_XOR_WriteProcessMemory_ffb0 {
  strings:
    $key_ffb0 = { a8 c2 [2] 9a e0 [2] 9c d5 [2] b2 d5 [2] 8d c9 }

  condition:
    any of them
}