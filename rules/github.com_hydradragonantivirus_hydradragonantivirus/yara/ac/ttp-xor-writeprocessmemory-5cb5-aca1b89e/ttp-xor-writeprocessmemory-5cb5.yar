rule TTP_XOR_WriteProcessMemory_5cb5 {
  strings:
    $key_5cb5 = { 0b c7 [2] 39 e5 [2] 3f d0 [2] 11 d0 [2] 2e cc }

  condition:
    any of them
}