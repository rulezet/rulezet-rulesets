rule TTP_XOR_WriteProcessMemory_b256 {
  strings:
    $key_b256 = { e5 24 [2] d7 06 [2] d1 33 [2] ff 33 [2] c0 2f }

  condition:
    any of them
}