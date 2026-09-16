rule TTP_XOR_WriteProcessMemory_0f17 {
  strings:
    $key_0f17 = { 58 65 [2] 6a 47 [2] 6c 72 [2] 42 72 [2] 7d 6e }

  condition:
    any of them
}