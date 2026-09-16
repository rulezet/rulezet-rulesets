rule TTP_XOR_WriteProcessMemory_0be0 {
  strings:
    $key_0be0 = { 5c 92 [2] 6e b0 [2] 68 85 [2] 46 85 [2] 79 99 }

  condition:
    any of them
}