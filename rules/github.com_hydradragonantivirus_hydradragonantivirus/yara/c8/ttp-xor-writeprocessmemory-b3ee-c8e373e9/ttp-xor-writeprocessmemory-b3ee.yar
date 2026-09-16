rule TTP_XOR_WriteProcessMemory_b3ee {
  strings:
    $key_b3ee = { e4 9c [2] d6 be [2] d0 8b [2] fe 8b [2] c1 97 }

  condition:
    any of them
}