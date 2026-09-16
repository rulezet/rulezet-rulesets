rule TTP_XOR_WriteProcessMemory_0fb5 {
  strings:
    $key_0fb5 = { 58 c7 [2] 6a e5 [2] 6c d0 [2] 42 d0 [2] 7d cc }

  condition:
    any of them
}