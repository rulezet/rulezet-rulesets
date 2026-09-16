rule TTP_XOR_WriteProcessMemory_0f13 {
  strings:
    $key_0f13 = { 58 61 [2] 6a 43 [2] 6c 76 [2] 42 76 [2] 7d 6a }

  condition:
    any of them
}