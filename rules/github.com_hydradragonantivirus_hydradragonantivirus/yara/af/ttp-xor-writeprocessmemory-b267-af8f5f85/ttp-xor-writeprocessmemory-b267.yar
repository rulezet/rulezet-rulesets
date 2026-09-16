rule TTP_XOR_WriteProcessMemory_b267 {
  strings:
    $key_b267 = { e5 15 [2] d7 37 [2] d1 02 [2] ff 02 [2] c0 1e }

  condition:
    any of them
}