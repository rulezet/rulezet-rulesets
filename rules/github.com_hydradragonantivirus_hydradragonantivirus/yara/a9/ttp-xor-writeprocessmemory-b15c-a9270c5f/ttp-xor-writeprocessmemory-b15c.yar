rule TTP_XOR_WriteProcessMemory_b15c {
  strings:
    $key_b15c = { e6 2e [2] d4 0c [2] d2 39 [2] fc 39 [2] c3 25 }

  condition:
    any of them
}