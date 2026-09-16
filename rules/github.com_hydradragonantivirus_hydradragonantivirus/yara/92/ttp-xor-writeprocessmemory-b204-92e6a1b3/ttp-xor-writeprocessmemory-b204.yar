rule TTP_XOR_WriteProcessMemory_b204 {
  strings:
    $key_b204 = { e5 76 [2] d7 54 [2] d1 61 [2] ff 61 [2] c0 7d }

  condition:
    any of them
}