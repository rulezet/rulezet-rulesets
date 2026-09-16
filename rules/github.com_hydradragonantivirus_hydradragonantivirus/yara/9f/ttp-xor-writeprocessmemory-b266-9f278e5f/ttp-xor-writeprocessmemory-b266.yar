rule TTP_XOR_WriteProcessMemory_b266 {
  strings:
    $key_b266 = { e5 14 [2] d7 36 [2] d1 03 [2] ff 03 [2] c0 1f }

  condition:
    any of them
}