rule TTP_XOR_WriteProcessMemory_b143 {
  strings:
    $key_b143 = { e6 31 [2] d4 13 [2] d2 26 [2] fc 26 [2] c3 3a }

  condition:
    any of them
}