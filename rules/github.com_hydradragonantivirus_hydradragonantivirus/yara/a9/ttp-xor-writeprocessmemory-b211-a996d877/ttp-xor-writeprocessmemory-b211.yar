rule TTP_XOR_WriteProcessMemory_b211 {
  strings:
    $key_b211 = { e5 63 [2] d7 41 [2] d1 74 [2] ff 74 [2] c0 68 }

  condition:
    any of them
}