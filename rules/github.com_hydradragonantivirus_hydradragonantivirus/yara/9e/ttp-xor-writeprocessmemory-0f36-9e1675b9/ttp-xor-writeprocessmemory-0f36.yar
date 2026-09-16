rule TTP_XOR_WriteProcessMemory_0f36 {
  strings:
    $key_0f36 = { 58 44 [2] 6a 66 [2] 6c 53 [2] 42 53 [2] 7d 4f }

  condition:
    any of them
}