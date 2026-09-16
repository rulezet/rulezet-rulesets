rule TTP_XOR_WriteProcessMemory_b101 {
  strings:
    $key_b101 = { e6 73 [2] d4 51 [2] d2 64 [2] fc 64 [2] c3 78 }

  condition:
    any of them
}