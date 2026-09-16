rule TTP_XOR_WriteProcessMemory_b385 {
  strings:
    $key_b385 = { e4 f7 [2] d6 d5 [2] d0 e0 [2] fe e0 [2] c1 fc }

  condition:
    any of them
}