rule TTP_XOR_WriteProcessMemory_b226 {
  strings:
    $key_b226 = { e5 54 [2] d7 76 [2] d1 43 [2] ff 43 [2] c0 5f }

  condition:
    any of them
}