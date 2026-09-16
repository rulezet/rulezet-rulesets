rule TTP_XOR_WriteProcessMemory_a517 {
  strings:
    $key_a517 = { f2 65 [2] c0 47 [2] c6 72 [2] e8 72 [2] d7 6e }

  condition:
    any of them
}