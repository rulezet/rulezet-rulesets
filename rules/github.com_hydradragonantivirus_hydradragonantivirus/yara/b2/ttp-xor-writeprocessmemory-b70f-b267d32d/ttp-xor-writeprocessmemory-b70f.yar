rule TTP_XOR_WriteProcessMemory_b70f {
  strings:
    $key_b70f = { e0 7d [2] d2 5f [2] d4 6a [2] fa 6a [2] c5 76 }

  condition:
    any of them
}