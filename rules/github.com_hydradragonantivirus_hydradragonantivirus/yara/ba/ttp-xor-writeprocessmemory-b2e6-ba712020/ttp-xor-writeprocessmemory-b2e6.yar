rule TTP_XOR_WriteProcessMemory_b2e6 {
  strings:
    $key_b2e6 = { e5 94 [2] d7 b6 [2] d1 83 [2] ff 83 [2] c0 9f }

  condition:
    any of them
}