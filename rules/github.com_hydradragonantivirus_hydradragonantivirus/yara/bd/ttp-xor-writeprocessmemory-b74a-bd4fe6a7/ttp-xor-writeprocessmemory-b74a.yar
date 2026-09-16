rule TTP_XOR_WriteProcessMemory_b74a {
  strings:
    $key_b74a = { e0 38 [2] d2 1a [2] d4 2f [2] fa 2f [2] c5 33 }

  condition:
    any of them
}