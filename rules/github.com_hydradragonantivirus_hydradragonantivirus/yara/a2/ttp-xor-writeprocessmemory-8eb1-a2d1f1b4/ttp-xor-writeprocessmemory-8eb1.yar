rule TTP_XOR_WriteProcessMemory_8eb1 {
  strings:
    $key_8eb1 = { d9 c3 [2] eb e1 [2] ed d4 [2] c3 d4 [2] fc c8 }

  condition:
    any of them
}