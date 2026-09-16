rule TTP_XOR_WriteProcessMemory_beb3 {
  strings:
    $key_beb3 = { e9 c1 [2] db e3 [2] dd d6 [2] f3 d6 [2] cc ca }

  condition:
    any of them
}