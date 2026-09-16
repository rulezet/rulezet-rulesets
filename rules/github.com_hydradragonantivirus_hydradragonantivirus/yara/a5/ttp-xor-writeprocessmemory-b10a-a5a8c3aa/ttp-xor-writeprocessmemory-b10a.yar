rule TTP_XOR_WriteProcessMemory_b10a {
  strings:
    $key_b10a = { e6 78 [2] d4 5a [2] d2 6f [2] fc 6f [2] c3 73 }

  condition:
    any of them
}