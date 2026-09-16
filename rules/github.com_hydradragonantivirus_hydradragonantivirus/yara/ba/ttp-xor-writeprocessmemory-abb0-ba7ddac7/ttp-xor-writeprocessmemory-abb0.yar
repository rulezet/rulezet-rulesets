rule TTP_XOR_WriteProcessMemory_abb0 {
  strings:
    $key_abb0 = { fc c2 [2] ce e0 [2] c8 d5 [2] e6 d5 [2] d9 c9 }

  condition:
    any of them
}