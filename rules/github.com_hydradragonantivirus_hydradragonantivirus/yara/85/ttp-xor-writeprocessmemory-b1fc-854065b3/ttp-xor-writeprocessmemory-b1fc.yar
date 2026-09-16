rule TTP_XOR_WriteProcessMemory_b1fc {
  strings:
    $key_b1fc = { e6 8e [2] d4 ac [2] d2 99 [2] fc 99 [2] c3 85 }

  condition:
    any of them
}