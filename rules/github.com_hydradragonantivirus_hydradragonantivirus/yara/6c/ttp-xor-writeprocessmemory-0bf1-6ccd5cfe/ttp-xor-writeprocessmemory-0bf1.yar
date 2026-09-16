rule TTP_XOR_WriteProcessMemory_0bf1 {
  strings:
    $key_0bf1 = { 5c 83 [2] 6e a1 [2] 68 94 [2] 46 94 [2] 79 88 }

  condition:
    any of them
}