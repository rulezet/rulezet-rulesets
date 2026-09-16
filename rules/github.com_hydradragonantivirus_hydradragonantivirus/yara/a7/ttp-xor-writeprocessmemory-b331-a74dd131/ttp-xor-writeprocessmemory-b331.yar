rule TTP_XOR_WriteProcessMemory_b331 {
  strings:
    $key_b331 = { e4 43 [2] d6 61 [2] d0 54 [2] fe 54 [2] c1 48 }

  condition:
    any of them
}