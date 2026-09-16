rule TTP_XOR_WriteProcessMemory_a457 {
  strings:
    $key_a457 = { f3 25 [2] c1 07 [2] c7 32 [2] e9 32 [2] d6 2e }

  condition:
    any of them
}