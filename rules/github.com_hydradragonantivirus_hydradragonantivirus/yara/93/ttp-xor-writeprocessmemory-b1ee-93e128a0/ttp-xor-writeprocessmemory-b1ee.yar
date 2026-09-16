rule TTP_XOR_WriteProcessMemory_b1ee {
  strings:
    $key_b1ee = { e6 9c [2] d4 be [2] d2 8b [2] fc 8b [2] c3 97 }

  condition:
    any of them
}