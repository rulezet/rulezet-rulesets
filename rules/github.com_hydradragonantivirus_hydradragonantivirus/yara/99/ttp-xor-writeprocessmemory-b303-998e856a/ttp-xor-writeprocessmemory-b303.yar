rule TTP_XOR_WriteProcessMemory_b303 {
  strings:
    $key_b303 = { e4 71 [2] d6 53 [2] d0 66 [2] fe 66 [2] c1 7a }

  condition:
    any of them
}