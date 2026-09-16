rule TTP_XOR_WriteProcessMemory_a55c {
  strings:
    $key_a55c = { f2 2e [2] c0 0c [2] c6 39 [2] e8 39 [2] d7 25 }

  condition:
    any of them
}