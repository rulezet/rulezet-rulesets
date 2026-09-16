rule TTP_XOR_WriteProcessMemory_b240 {
  strings:
    $key_b240 = { e5 32 [2] d7 10 [2] d1 25 [2] ff 25 [2] c0 39 }

  condition:
    any of them
}