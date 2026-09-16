rule TTP_XOR_WriteProcessMemory_b482 {
  strings:
    $key_b482 = { e3 f0 [2] d1 d2 [2] d7 e7 [2] f9 e7 [2] c6 fb }

  condition:
    any of them
}