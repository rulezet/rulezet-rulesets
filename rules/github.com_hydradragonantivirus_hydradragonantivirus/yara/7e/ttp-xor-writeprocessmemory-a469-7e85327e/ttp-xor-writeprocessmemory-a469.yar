rule TTP_XOR_WriteProcessMemory_a469 {
  strings:
    $key_a469 = { f3 1b [2] c1 39 [2] c7 0c [2] e9 0c [2] d6 10 }

  condition:
    any of them
}