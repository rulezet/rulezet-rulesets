rule TTP_XOR_WriteProcessMemory_b7fc {
  strings:
    $key_b7fc = { e0 8e [2] d2 ac [2] d4 99 [2] fa 99 [2] c5 85 }

  condition:
    any of them
}