rule TTP_XOR_WriteProcessMemory_b32c {
  strings:
    $key_b32c = { e4 5e [2] d6 7c [2] d0 49 [2] fe 49 [2] c1 55 }

  condition:
    any of them
}