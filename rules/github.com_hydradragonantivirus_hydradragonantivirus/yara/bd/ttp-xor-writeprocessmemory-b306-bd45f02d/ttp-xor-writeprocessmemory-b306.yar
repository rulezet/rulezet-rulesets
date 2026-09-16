rule TTP_XOR_WriteProcessMemory_b306 {
  strings:
    $key_b306 = { e4 74 [2] d6 56 [2] d0 63 [2] fe 63 [2] c1 7f }

  condition:
    any of them
}