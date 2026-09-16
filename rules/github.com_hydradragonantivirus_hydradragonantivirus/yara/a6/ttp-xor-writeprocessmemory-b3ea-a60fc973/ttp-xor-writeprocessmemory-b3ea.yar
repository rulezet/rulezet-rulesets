rule TTP_XOR_WriteProcessMemory_b3ea {
  strings:
    $key_b3ea = { e4 98 [2] d6 ba [2] d0 8f [2] fe 8f [2] c1 93 }

  condition:
    any of them
}