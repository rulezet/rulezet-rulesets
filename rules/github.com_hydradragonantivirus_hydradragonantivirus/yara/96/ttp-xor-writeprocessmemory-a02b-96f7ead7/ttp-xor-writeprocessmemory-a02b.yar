rule TTP_XOR_WriteProcessMemory_a02b {
  strings:
    $key_a02b = { f7 59 [2] c5 7b [2] c3 4e [2] ed 4e [2] d2 52 }

  condition:
    any of them
}