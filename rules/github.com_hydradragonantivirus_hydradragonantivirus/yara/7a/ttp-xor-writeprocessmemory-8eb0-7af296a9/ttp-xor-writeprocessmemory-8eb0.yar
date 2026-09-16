rule TTP_XOR_WriteProcessMemory_8eb0 {
  strings:
    $key_8eb0 = { d9 c2 [2] eb e0 [2] ed d5 [2] c3 d5 [2] fc c9 }

  condition:
    any of them
}