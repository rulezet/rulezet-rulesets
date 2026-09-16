rule TTP_XOR_WriteProcessMemory_b12a {
  strings:
    $key_b12a = { e6 58 [2] d4 7a [2] d2 4f [2] fc 4f [2] c3 53 }

  condition:
    any of them
}