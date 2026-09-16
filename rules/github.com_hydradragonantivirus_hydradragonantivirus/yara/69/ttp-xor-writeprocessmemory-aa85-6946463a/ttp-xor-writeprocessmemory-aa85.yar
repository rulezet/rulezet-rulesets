rule TTP_XOR_WriteProcessMemory_aa85 {
  strings:
    $key_aa85 = { fd f7 [2] cf d5 [2] c9 e0 [2] e7 e0 [2] d8 fc }

  condition:
    any of them
}