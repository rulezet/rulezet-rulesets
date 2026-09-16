rule TTP_XOR_WriteProcessMemory_ec85 {
  strings:
    $key_ec85 = { bb f7 [2] 89 d5 [2] 8f e0 [2] a1 e0 [2] 9e fc }

  condition:
    any of them
}