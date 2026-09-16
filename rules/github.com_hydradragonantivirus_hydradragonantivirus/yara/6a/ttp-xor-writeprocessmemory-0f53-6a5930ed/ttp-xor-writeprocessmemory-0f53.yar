rule TTP_XOR_WriteProcessMemory_0f53 {
  strings:
    $key_0f53 = { 58 21 [2] 6a 03 [2] 6c 36 [2] 42 36 [2] 7d 2a }

  condition:
    any of them
}