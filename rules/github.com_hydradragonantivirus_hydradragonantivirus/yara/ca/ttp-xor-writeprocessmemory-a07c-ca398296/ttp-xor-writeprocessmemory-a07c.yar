rule TTP_XOR_WriteProcessMemory_a07c {
  strings:
    $key_a07c = { f7 0e [2] c5 2c [2] c3 19 [2] ed 19 [2] d2 05 }

  condition:
    any of them
}