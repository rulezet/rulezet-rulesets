rule TTP_XOR_WriteProcessMemory_b242 {
  strings:
    $key_b242 = { e5 30 [2] d7 12 [2] d1 27 [2] ff 27 [2] c0 3b }

  condition:
    any of them
}