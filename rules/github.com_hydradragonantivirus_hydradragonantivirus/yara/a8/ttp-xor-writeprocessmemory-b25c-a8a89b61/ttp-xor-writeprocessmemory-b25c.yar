rule TTP_XOR_WriteProcessMemory_b25c {
  strings:
    $key_b25c = { e5 2e [2] d7 0c [2] d1 39 [2] ff 39 [2] c0 25 }

  condition:
    any of them
}