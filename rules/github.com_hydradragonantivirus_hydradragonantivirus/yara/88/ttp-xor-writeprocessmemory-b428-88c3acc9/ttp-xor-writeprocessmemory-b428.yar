rule TTP_XOR_WriteProcessMemory_b428 {
  strings:
    $key_b428 = { e3 5a [2] d1 78 [2] d7 4d [2] f9 4d [2] c6 51 }

  condition:
    any of them
}