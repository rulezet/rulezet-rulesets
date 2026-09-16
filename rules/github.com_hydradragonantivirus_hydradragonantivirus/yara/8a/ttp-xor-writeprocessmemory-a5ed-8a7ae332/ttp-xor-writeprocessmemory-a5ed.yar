rule TTP_XOR_WriteProcessMemory_a5ed {
  strings:
    $key_a5ed = { f2 9f [2] c0 bd [2] c6 88 [2] e8 88 [2] d7 94 }

  condition:
    any of them
}