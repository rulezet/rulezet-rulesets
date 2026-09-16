rule TTP_XOR_WriteProcessMemory_b217 {
  strings:
    $key_b217 = { e5 65 [2] d7 47 [2] d1 72 [2] ff 72 [2] c0 6e }

  condition:
    any of them
}