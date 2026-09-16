rule TTP_XOR_WriteProcessMemory_abb2 {
  strings:
    $key_abb2 = { fc c0 [2] ce e2 [2] c8 d7 [2] e6 d7 [2] d9 cb }

  condition:
    any of them
}