rule TTP_XOR_WriteProcessMemory_b317 {
  strings:
    $key_b317 = { e4 65 [2] d6 47 [2] d0 72 [2] fe 72 [2] c1 6e }

  condition:
    any of them
}