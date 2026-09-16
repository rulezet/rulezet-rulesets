rule TTP_XOR_WriteProcessMemory_a6ee {
  strings:
    $key_a6ee = { f1 9c [2] c3 be [2] c5 8b [2] eb 8b [2] d4 97 }

  condition:
    any of them
}