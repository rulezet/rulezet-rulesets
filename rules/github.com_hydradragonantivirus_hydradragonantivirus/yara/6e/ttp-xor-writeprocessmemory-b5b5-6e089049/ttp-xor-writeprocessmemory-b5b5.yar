rule TTP_XOR_WriteProcessMemory_b5b5 {
  strings:
    $key_b5b5 = { e2 c7 [2] d0 e5 [2] d6 d0 [2] f8 d0 [2] c7 cc }

  condition:
    any of them
}