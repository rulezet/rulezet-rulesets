rule TTP_XOR_WriteProcessMemory_a01c {
  strings:
    $key_a01c = { f7 6e [2] c5 4c [2] c3 79 [2] ed 79 [2] d2 65 }

  condition:
    any of them
}