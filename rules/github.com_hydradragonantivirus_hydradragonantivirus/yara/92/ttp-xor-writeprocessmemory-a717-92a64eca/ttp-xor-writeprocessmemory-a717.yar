rule TTP_XOR_WriteProcessMemory_a717 {
  strings:
    $key_a717 = { f0 65 [2] c2 47 [2] c4 72 [2] ea 72 [2] d5 6e }

  condition:
    any of them
}