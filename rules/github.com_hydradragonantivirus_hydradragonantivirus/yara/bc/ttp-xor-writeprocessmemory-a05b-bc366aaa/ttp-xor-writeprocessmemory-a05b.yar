rule TTP_XOR_WriteProcessMemory_a05b {
  strings:
    $key_a05b = { f7 29 [2] c5 0b [2] c3 3e [2] ed 3e [2] d2 22 }

  condition:
    any of them
}