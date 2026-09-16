rule TTP_XOR_WriteProcessMemory_b72c {
  strings:
    $key_b72c = { e0 5e [2] d2 7c [2] d4 49 [2] fa 49 [2] c5 55 }

  condition:
    any of them
}