rule TTP_XOR_WriteProcessMemory_b4b5 {
  strings:
    $key_b4b5 = { e3 c7 [2] d1 e5 [2] d7 d0 [2] f9 d0 [2] c6 cc }

  condition:
    any of them
}