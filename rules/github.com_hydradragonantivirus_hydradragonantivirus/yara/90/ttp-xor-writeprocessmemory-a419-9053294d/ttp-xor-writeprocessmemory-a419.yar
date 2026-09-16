rule TTP_XOR_WriteProcessMemory_a419 {
  strings:
    $key_a419 = { f3 6b [2] c1 49 [2] c7 7c [2] e9 7c [2] d6 60 }

  condition:
    any of them
}