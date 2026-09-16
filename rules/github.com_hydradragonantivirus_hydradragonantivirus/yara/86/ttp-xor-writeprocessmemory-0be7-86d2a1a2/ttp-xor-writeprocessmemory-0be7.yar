rule TTP_XOR_WriteProcessMemory_0be7 {
  strings:
    $key_0be7 = { 5c 95 [2] 6e b7 [2] 68 82 [2] 46 82 [2] 79 9e }

  condition:
    any of them
}