rule TTP_XOR_WriteProcessMemory_1fb5 {
  strings:
    $key_1fb5 = { 48 c7 [2] 7a e5 [2] 7c d0 [2] 52 d0 [2] 6d cc }

  condition:
    any of them
}