rule TTP_XOR_WriteProcessMemory_b18b {
  strings:
    $key_b18b = { e6 f9 [2] d4 db [2] d2 ee [2] fc ee [2] c3 f2 }

  condition:
    any of them
}