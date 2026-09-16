rule TTP_XOR_WriteProcessMemory_b3fd {
  strings:
    $key_b3fd = { e4 8f [2] d6 ad [2] d0 98 [2] fe 98 [2] c1 84 }

  condition:
    any of them
}