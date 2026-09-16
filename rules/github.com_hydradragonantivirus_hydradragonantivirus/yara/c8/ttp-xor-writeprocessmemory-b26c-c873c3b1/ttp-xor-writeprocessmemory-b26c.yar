rule TTP_XOR_WriteProcessMemory_b26c {
  strings:
    $key_b26c = { e5 1e [2] d7 3c [2] d1 09 [2] ff 09 [2] c0 15 }

  condition:
    any of them
}