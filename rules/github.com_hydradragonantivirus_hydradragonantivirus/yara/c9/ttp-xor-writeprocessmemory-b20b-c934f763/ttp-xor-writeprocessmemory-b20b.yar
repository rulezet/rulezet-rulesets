rule TTP_XOR_WriteProcessMemory_b20b {
  strings:
    $key_b20b = { e5 79 [2] d7 5b [2] d1 6e [2] ff 6e [2] c0 72 }

  condition:
    any of them
}