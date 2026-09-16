rule TTP_XOR_WriteProcessMemory_b586 {
  strings:
    $key_b586 = { e2 f4 [2] d0 d6 [2] d6 e3 [2] f8 e3 [2] c7 ff }

  condition:
    any of them
}