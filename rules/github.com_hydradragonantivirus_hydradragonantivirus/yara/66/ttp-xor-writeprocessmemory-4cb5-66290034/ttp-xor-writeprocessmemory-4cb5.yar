rule TTP_XOR_WriteProcessMemory_4cb5 {
  strings:
    $key_4cb5 = { 1b c7 [2] 29 e5 [2] 2f d0 [2] 01 d0 [2] 3e cc }

  condition:
    any of them
}