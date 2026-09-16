rule TTP_XOR_WriteProcessMemory_a4a8 {
  strings:
    $key_a4a8 = { f3 da [2] c1 f8 [2] c7 cd [2] e9 cd [2] d6 d1 }

  condition:
    any of them
}