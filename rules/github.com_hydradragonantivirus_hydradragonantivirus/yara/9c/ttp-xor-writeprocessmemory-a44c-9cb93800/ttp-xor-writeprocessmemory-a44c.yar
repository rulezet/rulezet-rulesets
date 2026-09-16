rule TTP_XOR_WriteProcessMemory_a44c {
  strings:
    $key_a44c = { f3 3e [2] c1 1c [2] c7 29 [2] e9 29 [2] d6 35 }

  condition:
    any of them
}