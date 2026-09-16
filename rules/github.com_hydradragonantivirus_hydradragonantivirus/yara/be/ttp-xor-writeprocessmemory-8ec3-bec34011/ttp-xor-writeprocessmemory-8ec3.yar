rule TTP_XOR_WriteProcessMemory_8ec3 {
  strings:
    $key_8ec3 = { d9 b1 [2] eb 93 [2] ed a6 [2] c3 a6 [2] fc ba }

  condition:
    any of them
}