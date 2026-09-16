rule TTP_XOR_WriteProcessMemory_b35c {
  strings:
    $key_b35c = { e4 2e [2] d6 0c [2] d0 39 [2] fe 39 [2] c1 25 }

  condition:
    any of them
}