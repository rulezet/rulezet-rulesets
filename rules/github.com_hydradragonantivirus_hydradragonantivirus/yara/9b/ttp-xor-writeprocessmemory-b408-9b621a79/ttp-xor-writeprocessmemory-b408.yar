rule TTP_XOR_WriteProcessMemory_b408 {
  strings:
    $key_b408 = { e3 7a [2] d1 58 [2] d7 6d [2] f9 6d [2] c6 71 }

  condition:
    any of them
}