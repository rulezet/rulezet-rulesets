rule TTP_XOR_WriteProcessMemory_b233 {
  strings:
    $key_b233 = { e5 41 [2] d7 63 [2] d1 56 [2] ff 56 [2] c0 4a }

  condition:
    any of them
}