rule TTP_XOR_WriteProcessMemory_b7cb {
  strings:
    $key_b7cb = { e0 b9 [2] d2 9b [2] d4 ae [2] fa ae [2] c5 b2 }

  condition:
    any of them
}