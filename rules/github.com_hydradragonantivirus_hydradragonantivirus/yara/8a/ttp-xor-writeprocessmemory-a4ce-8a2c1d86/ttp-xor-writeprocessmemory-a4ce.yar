rule TTP_XOR_WriteProcessMemory_a4ce {
  strings:
    $key_a4ce = { f3 bc [2] c1 9e [2] c7 ab [2] e9 ab [2] d6 b7 }

  condition:
    any of them
}