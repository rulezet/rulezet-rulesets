rule TTP_XOR_WriteProcessMemory_b113 {
  strings:
    $key_b113 = { e6 61 [2] d4 43 [2] d2 76 [2] fc 76 [2] c3 6a }

  condition:
    any of them
}