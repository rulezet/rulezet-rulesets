rule TTP_XOR_WriteProcessMemory_b7e9 {
  strings:
    $key_b7e9 = { e0 9b [2] d2 b9 [2] d4 8c [2] fa 8c [2] c5 90 }

  condition:
    any of them
}