rule TTP_XOR_WriteProcessMemory_b27c {
  strings:
    $key_b27c = { e5 0e [2] d7 2c [2] d1 19 [2] ff 19 [2] c0 05 }

  condition:
    any of them
}