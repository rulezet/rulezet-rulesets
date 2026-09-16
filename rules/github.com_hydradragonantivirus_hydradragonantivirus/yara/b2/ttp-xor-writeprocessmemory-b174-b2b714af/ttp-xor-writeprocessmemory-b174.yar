rule TTP_XOR_WriteProcessMemory_b174 {
  strings:
    $key_b174 = { e6 06 [2] d4 24 [2] d2 11 [2] fc 11 [2] c3 0d }

  condition:
    any of them
}