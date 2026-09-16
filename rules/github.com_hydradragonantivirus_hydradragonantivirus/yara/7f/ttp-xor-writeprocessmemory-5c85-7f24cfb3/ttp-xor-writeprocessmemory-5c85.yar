rule TTP_XOR_WriteProcessMemory_5c85 {
  strings:
    $key_5c85 = { 0b f7 [2] 39 d5 [2] 3f e0 [2] 11 e0 [2] 2e fc }

  condition:
    any of them
}