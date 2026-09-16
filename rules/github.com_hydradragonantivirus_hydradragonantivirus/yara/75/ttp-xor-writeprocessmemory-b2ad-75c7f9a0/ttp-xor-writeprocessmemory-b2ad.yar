rule TTP_XOR_WriteProcessMemory_b2ad {
  strings:
    $key_b2ad = { e5 df [2] d7 fd [2] d1 c8 [2] ff c8 [2] c0 d4 }

  condition:
    any of them
}