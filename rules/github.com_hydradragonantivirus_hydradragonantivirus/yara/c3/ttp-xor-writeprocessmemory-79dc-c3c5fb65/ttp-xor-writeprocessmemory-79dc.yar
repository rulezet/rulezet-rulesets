rule TTP_XOR_WriteProcessMemory_79dc {
  strings:
    $key_79dc = { 2e ae [2] 1c 8c [2] 1a b9 [2] 34 b9 [2] 0b a5 }

  condition:
    any of them
}