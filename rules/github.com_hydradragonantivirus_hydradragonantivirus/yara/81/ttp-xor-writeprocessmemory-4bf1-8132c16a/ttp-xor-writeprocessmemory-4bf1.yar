rule TTP_XOR_WriteProcessMemory_4bf1 {
  strings:
    $key_4bf1 = { 1c 83 [2] 2e a1 [2] 28 94 [2] 06 94 [2] 39 88 }

  condition:
    any of them
}