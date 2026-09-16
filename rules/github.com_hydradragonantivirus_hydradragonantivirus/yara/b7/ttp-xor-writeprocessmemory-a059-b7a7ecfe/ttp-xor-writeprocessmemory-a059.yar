rule TTP_XOR_WriteProcessMemory_a059 {
  strings:
    $key_a059 = { f7 2b [2] c5 09 [2] c3 3c [2] ed 3c [2] d2 20 }

  condition:
    any of them
}