rule TTP_XOR_WriteProcessMemory_a7fd {
  strings:
    $key_a7fd = { f0 8f [2] c2 ad [2] c4 98 [2] ea 98 [2] d5 84 }

  condition:
    any of them
}