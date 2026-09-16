rule TTP_XOR_WriteProcessMemory_b210 {
  strings:
    $key_b210 = { e5 62 [2] d7 40 [2] d1 75 [2] ff 75 [2] c0 69 }

  condition:
    any of them
}