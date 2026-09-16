rule TTP_XOR_WriteProcessMemory_4cdc {
  strings:
    $key_4cdc = { 1b ae [2] 29 8c [2] 2f b9 [2] 01 b9 [2] 3e a5 }

  condition:
    any of them
}