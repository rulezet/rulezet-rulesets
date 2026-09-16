rule TTP_XOR_WriteProcessMemory_a069 {
  strings:
    $key_a069 = { f7 1b [2] c5 39 [2] c3 0c [2] ed 0c [2] d2 10 }

  condition:
    any of them
}