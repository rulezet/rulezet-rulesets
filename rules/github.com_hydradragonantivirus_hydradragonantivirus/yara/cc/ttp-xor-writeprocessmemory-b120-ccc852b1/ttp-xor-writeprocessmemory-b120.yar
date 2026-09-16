rule TTP_XOR_WriteProcessMemory_b120 {
  strings:
    $key_b120 = { e6 52 [2] d4 70 [2] d2 45 [2] fc 45 [2] c3 59 }

  condition:
    any of them
}