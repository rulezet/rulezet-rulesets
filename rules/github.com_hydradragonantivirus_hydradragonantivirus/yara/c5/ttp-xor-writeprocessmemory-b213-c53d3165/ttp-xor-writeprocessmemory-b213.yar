rule TTP_XOR_WriteProcessMemory_b213 {
  strings:
    $key_b213 = { e5 61 [2] d7 43 [2] d1 76 [2] ff 76 [2] c0 6a }

  condition:
    any of them
}