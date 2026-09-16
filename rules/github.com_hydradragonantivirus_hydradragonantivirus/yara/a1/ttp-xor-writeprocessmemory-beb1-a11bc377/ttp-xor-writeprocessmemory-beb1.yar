rule TTP_XOR_WriteProcessMemory_beb1 {
  strings:
    $key_beb1 = { e9 c3 [2] db e1 [2] dd d4 [2] f3 d4 [2] cc c8 }

  condition:
    any of them
}