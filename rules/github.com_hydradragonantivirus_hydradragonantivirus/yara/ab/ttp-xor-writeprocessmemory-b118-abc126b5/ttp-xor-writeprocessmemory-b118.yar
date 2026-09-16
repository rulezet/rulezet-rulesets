rule TTP_XOR_WriteProcessMemory_b118 {
  strings:
    $key_b118 = { e6 6a [2] d4 48 [2] d2 7d [2] fc 7d [2] c3 61 }

  condition:
    any of them
}