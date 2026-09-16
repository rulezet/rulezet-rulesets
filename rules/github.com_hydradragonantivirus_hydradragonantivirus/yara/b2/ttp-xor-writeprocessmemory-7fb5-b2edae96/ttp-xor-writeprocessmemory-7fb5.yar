rule TTP_XOR_WriteProcessMemory_7fb5 {
  strings:
    $key_7fb5 = { 28 c7 [2] 1a e5 [2] 1c d0 [2] 32 d0 [2] 0d cc }

  condition:
    any of them
}