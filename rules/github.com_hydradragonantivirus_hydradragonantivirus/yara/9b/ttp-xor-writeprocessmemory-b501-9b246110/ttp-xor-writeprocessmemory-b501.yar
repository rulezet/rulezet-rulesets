rule TTP_XOR_WriteProcessMemory_b501 {
  strings:
    $key_b501 = { e2 73 [2] d0 51 [2] d6 64 [2] f8 64 [2] c7 78 }

  condition:
    any of them
}