rule TTP_XOR_WriteProcessMemory_a2a8 {
  strings:
    $key_a2a8 = { f5 da [2] c7 f8 [2] c1 cd [2] ef cd [2] d0 d1 }

  condition:
    any of them
}