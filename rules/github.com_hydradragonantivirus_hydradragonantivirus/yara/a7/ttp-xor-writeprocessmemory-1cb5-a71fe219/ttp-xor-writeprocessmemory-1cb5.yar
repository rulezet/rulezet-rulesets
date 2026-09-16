rule TTP_XOR_WriteProcessMemory_1cb5 {
  strings:
    $key_1cb5 = { 4b c7 [2] 79 e5 [2] 7f d0 [2] 51 d0 [2] 6e cc }

  condition:
    any of them
}