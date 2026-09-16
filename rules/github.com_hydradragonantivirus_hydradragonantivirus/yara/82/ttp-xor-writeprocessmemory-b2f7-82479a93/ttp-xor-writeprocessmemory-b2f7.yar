rule TTP_XOR_WriteProcessMemory_b2f7 {
  strings:
    $key_b2f7 = { e5 85 [2] d7 a7 [2] d1 92 [2] ff 92 [2] c0 8e }

  condition:
    any of them
}