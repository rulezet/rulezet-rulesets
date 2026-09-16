rule TTP_XOR_WriteProcessMemory_49dc {
  strings:
    $key_49dc = { 1e ae [2] 2c 8c [2] 2a b9 [2] 04 b9 [2] 3b a5 }

  condition:
    any of them
}