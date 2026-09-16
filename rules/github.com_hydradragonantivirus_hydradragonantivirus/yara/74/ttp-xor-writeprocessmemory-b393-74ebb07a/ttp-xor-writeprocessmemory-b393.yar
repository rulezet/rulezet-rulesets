rule TTP_XOR_WriteProcessMemory_b393 {
  strings:
    $key_b393 = { e4 e1 [2] d6 c3 [2] d0 f6 [2] fe f6 [2] c1 ea }

  condition:
    any of them
}