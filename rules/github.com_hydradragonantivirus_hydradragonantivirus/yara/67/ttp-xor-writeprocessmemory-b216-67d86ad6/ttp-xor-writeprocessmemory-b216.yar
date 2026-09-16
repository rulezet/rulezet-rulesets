rule TTP_XOR_WriteProcessMemory_b216 {
  strings:
    $key_b216 = { e5 64 [2] d7 46 [2] d1 73 [2] ff 73 [2] c0 6f }

  condition:
    any of them
}