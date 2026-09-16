rule TTP_XOR_WriteProcessMemory_b2c7 {
  strings:
    $key_b2c7 = { e5 b5 [2] d7 97 [2] d1 a2 [2] ff a2 [2] c0 be }

  condition:
    any of them
}