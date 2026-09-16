rule TTP_XOR_WriteProcessMemory_5fb5 {
  strings:
    $key_5fb5 = { 08 c7 [2] 3a e5 [2] 3c d0 [2] 12 d0 [2] 2d cc }

  condition:
    any of them
}