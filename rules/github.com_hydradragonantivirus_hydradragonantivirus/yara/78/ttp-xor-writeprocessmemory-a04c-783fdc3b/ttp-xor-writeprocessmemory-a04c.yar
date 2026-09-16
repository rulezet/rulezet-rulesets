rule TTP_XOR_WriteProcessMemory_a04c {
  strings:
    $key_a04c = { f7 3e [2] c5 1c [2] c3 29 [2] ed 29 [2] d2 35 }

  condition:
    any of them
}