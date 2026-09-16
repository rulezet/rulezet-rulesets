rule TTP_XOR_WriteProcessMemory_b71a {
  strings:
    $key_b71a = { e0 68 [2] d2 4a [2] d4 7f [2] fa 7f [2] c5 63 }

  condition:
    any of them
}