rule TTP_XOR_WriteProcessMemory_b73a {
  strings:
    $key_b73a = { e0 48 [2] d2 6a [2] d4 5f [2] fa 5f [2] c5 43 }

  condition:
    any of them
}