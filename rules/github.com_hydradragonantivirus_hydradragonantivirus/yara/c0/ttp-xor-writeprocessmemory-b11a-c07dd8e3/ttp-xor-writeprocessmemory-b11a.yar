rule TTP_XOR_WriteProcessMemory_b11a {
  strings:
    $key_b11a = { e6 68 [2] d4 4a [2] d2 7f [2] fc 7f [2] c3 63 }

  condition:
    any of them
}