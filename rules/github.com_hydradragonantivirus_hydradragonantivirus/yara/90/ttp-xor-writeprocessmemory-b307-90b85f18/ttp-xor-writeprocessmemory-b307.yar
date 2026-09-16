rule TTP_XOR_WriteProcessMemory_b307 {
  strings:
    $key_b307 = { e4 75 [2] d6 57 [2] d0 62 [2] fe 62 [2] c1 7e }

  condition:
    any of them
}