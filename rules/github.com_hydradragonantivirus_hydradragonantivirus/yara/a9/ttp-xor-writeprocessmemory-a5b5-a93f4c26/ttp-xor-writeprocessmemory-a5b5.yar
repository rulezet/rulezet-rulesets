rule TTP_XOR_WriteProcessMemory_a5b5 {
  strings:
    $key_a5b5 = { f2 c7 [2] c0 e5 [2] c6 d0 [2] e8 d0 [2] d7 cc }

  condition:
    any of them
}