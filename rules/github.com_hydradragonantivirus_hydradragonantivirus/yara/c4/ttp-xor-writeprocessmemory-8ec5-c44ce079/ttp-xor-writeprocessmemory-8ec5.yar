rule TTP_XOR_WriteProcessMemory_8ec5 {
  strings:
    $key_8ec5 = { d9 b7 [2] eb 95 [2] ed a0 [2] c3 a0 [2] fc bc }

  condition:
    any of them
}