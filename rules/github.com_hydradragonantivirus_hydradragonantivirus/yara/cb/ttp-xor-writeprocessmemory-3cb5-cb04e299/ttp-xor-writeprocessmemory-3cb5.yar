rule TTP_XOR_WriteProcessMemory_3cb5 {
  strings:
    $key_3cb5 = { 6b c7 [2] 59 e5 [2] 5f d0 [2] 71 d0 [2] 4e cc }

  condition:
    any of them
}