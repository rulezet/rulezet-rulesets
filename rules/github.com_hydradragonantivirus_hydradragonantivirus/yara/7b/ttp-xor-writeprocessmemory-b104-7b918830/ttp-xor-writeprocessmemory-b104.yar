rule TTP_XOR_WriteProcessMemory_b104 {
  strings:
    $key_b104 = { e6 76 [2] d4 54 [2] d2 61 [2] fc 61 [2] c3 7d }

  condition:
    any of them
}