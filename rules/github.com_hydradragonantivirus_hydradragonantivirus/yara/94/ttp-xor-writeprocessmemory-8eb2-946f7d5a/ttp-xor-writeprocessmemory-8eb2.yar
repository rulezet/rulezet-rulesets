rule TTP_XOR_WriteProcessMemory_8eb2 {
  strings:
    $key_8eb2 = { d9 c0 [2] eb e2 [2] ed d7 [2] c3 d7 [2] fc cb }

  condition:
    any of them
}