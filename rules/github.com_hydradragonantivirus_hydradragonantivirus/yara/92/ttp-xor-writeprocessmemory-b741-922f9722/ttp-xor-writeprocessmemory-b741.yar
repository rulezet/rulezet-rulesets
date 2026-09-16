rule TTP_XOR_WriteProcessMemory_b741 {
  strings:
    $key_b741 = { e0 33 [2] d2 11 [2] d4 24 [2] fa 24 [2] c5 38 }

  condition:
    any of them
}