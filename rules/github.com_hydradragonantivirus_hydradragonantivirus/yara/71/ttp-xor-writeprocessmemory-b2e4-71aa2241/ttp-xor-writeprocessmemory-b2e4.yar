rule TTP_XOR_WriteProcessMemory_b2e4 {
  strings:
    $key_b2e4 = { e5 96 [2] d7 b4 [2] d1 81 [2] ff 81 [2] c0 9d }

  condition:
    any of them
}