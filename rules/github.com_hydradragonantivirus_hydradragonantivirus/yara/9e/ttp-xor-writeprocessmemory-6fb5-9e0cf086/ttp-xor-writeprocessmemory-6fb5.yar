rule TTP_XOR_WriteProcessMemory_6fb5 {
  strings:
    $key_6fb5 = { 38 c7 [2] 0a e5 [2] 0c d0 [2] 22 d0 [2] 1d cc }

  condition:
    any of them
}