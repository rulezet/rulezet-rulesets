rule TTP_XOR_WriteProcessMemory_4be7 {
  strings:
    $key_4be7 = { 1c 95 [2] 2e b7 [2] 28 82 [2] 06 82 [2] 39 9e }

  condition:
    any of them
}