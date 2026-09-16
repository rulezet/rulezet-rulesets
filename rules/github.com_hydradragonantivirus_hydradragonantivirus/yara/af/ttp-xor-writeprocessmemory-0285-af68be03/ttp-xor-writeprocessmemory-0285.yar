rule TTP_XOR_WriteProcessMemory_0285 {
  strings:
    $key_0285 = { 55 f7 [2] 67 d5 [2] 61 e0 [2] 4f e0 [2] 70 fc }

  condition:
    any of them
}