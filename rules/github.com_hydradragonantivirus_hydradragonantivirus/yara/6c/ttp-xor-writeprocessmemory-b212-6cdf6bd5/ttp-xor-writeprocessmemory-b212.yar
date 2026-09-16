rule TTP_XOR_WriteProcessMemory_b212 {
  strings:
    $key_b212 = { e5 60 [2] d7 42 [2] d1 77 [2] ff 77 [2] c0 6b }

  condition:
    any of them
}