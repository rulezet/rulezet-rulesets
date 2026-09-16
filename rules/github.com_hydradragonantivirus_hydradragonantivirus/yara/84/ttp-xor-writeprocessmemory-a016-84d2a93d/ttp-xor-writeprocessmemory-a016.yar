rule TTP_XOR_WriteProcessMemory_a016 {
  strings:
    $key_a016 = { f7 64 [2] c5 46 [2] c3 73 [2] ed 73 [2] d2 6f }

  condition:
    any of them
}