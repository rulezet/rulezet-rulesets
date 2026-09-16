rule TTP_XOR_WriteProcessMemory_0f03 {
  strings:
    $key_0f03 = { 58 71 [2] 6a 53 [2] 6c 66 [2] 42 66 [2] 7d 7a }

  condition:
    any of them
}