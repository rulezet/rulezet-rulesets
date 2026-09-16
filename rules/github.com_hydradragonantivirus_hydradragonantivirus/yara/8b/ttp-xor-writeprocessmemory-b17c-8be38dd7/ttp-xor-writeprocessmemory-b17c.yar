rule TTP_XOR_WriteProcessMemory_b17c {
  strings:
    $key_b17c = { e6 0e [2] d4 2c [2] d2 19 [2] fc 19 [2] c3 05 }

  condition:
    any of them
}