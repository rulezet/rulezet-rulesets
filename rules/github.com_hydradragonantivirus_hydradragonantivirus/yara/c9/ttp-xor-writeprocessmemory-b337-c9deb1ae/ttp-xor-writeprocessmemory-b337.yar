rule TTP_XOR_WriteProcessMemory_b337 {
  strings:
    $key_b337 = { e4 45 [2] d6 67 [2] d0 52 [2] fe 52 [2] c1 4e }

  condition:
    any of them
}