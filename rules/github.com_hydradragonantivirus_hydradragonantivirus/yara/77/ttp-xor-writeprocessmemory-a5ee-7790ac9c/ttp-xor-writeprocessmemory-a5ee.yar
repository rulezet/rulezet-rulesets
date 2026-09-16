rule TTP_XOR_WriteProcessMemory_a5ee {
  strings:
    $key_a5ee = { f2 9c [2] c0 be [2] c6 8b [2] e8 8b [2] d7 97 }

  condition:
    any of them
}