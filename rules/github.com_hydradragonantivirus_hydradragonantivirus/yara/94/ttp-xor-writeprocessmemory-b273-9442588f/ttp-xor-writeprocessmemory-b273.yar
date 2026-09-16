rule TTP_XOR_WriteProcessMemory_b273 {
  strings:
    $key_b273 = { e5 01 [2] d7 23 [2] d1 16 [2] ff 16 [2] c0 0a }

  condition:
    any of them
}