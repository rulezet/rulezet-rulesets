rule TTP_XOR_WriteProcessMemory_b722 {
  strings:
    $key_b722 = { e0 50 [2] d2 72 [2] d4 47 [2] fa 47 [2] c5 5b }

  condition:
    any of them
}