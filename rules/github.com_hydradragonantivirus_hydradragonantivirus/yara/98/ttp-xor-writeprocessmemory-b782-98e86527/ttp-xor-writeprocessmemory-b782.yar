rule TTP_XOR_WriteProcessMemory_b782 {
  strings:
    $key_b782 = { e0 f0 [2] d2 d2 [2] d4 e7 [2] fa e7 [2] c5 fb }

  condition:
    any of them
}