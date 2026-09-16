rule TTP_XOR_WriteProcessMemory_7285 {
  strings:
    $key_7285 = { 25 f7 [2] 17 d5 [2] 11 e0 [2] 3f e0 [2] 00 fc }

  condition:
    any of them
}