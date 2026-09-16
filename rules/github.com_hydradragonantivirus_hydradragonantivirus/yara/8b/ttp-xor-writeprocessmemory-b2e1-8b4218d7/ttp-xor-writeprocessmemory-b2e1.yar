rule TTP_XOR_WriteProcessMemory_b2e1 {
  strings:
    $key_b2e1 = { e5 93 [2] d7 b1 [2] d1 84 [2] ff 84 [2] c0 98 }

  condition:
    any of them
}