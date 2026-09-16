rule TTP_XOR_WriteProcessMemory_b394 {
  strings:
    $key_b394 = { e4 e6 [2] d6 c4 [2] d0 f1 [2] fe f1 [2] c1 ed }

  condition:
    any of them
}