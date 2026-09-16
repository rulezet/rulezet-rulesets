rule TTP_XOR_WriteProcessMemory_1cdc {
  strings:
    $key_1cdc = { 4b ae [2] 79 8c [2] 7f b9 [2] 51 b9 [2] 6e a5 }

  condition:
    any of them
}