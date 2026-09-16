rule TTP_XOR_WriteProcessMemory_a3a8 {
  strings:
    $key_a3a8 = { f4 da [2] c6 f8 [2] c0 cd [2] ee cd [2] d1 d1 }

  condition:
    any of them
}