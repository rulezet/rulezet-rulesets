rule TTP_XOR_WriteProcessMemory_b14a {
  strings:
    $key_b14a = { e6 38 [2] d4 1a [2] d2 2f [2] fc 2f [2] c3 33 }

  condition:
    any of them
}