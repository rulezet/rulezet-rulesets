rule TTP_XOR_WriteProcessMemory_b263 {
  strings:
    $key_b263 = { e5 11 [2] d7 33 [2] d1 06 [2] ff 06 [2] c0 1a }

  condition:
    any of them
}