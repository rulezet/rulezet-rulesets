rule TTP_XOR_WriteProcessMemory_b220 {
  strings:
    $key_b220 = { e5 52 [2] d7 70 [2] d1 45 [2] ff 45 [2] c0 59 }

  condition:
    any of them
}