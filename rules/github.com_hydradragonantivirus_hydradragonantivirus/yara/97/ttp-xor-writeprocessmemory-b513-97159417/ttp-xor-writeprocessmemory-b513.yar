rule TTP_XOR_WriteProcessMemory_b513 {
  strings:
    $key_b513 = { e2 61 [2] d0 43 [2] d6 76 [2] f8 76 [2] c7 6a }

  condition:
    any of them
}