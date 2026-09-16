rule TTP_XOR_WriteProcessMemory_b30c {
  strings:
    $key_b30c = { e4 7e [2] d6 5c [2] d0 69 [2] fe 69 [2] c1 75 }

  condition:
    any of them
}