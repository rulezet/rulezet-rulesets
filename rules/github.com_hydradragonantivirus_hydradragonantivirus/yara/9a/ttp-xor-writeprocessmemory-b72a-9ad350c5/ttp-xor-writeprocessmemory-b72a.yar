rule TTP_XOR_WriteProcessMemory_b72a {
  strings:
    $key_b72a = { e0 58 [2] d2 7a [2] d4 4f [2] fa 4f [2] c5 53 }

  condition:
    any of them
}