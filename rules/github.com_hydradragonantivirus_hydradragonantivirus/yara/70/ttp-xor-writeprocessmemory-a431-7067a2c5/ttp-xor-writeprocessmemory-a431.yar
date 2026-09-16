rule TTP_XOR_WriteProcessMemory_a431 {
  strings:
    $key_a431 = { f3 43 [2] c1 61 [2] c7 54 [2] e9 54 [2] d6 48 }

  condition:
    any of them
}