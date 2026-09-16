rule TTP_XOR_WriteProcessMemory_a079 {
  strings:
    $key_a079 = { f7 0b [2] c5 29 [2] c3 1c [2] ed 1c [2] d2 00 }

  condition:
    any of them
}