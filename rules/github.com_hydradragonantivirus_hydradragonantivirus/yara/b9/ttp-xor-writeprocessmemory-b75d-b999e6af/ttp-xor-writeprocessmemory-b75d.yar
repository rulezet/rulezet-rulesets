rule TTP_XOR_WriteProcessMemory_b75d {
  strings:
    $key_b75d = { e0 2f [2] d2 0d [2] d4 38 [2] fa 38 [2] c5 24 }

  condition:
    any of them
}