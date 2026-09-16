rule TTP_XOR_WriteProcessMemory_8eb5 {
  strings:
    $key_8eb5 = { d9 c7 [2] eb e5 [2] ed d0 [2] c3 d0 [2] fc cc }

  condition:
    any of them
}