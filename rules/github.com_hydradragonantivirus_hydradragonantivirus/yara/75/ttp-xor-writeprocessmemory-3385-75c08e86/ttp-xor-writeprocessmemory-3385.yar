rule TTP_XOR_WriteProcessMemory_3385 {
  strings:
    $key_3385 = { 64 f7 [2] 56 d5 [2] 50 e0 [2] 7e e0 [2] 41 fc }

  condition:
    any of them
}