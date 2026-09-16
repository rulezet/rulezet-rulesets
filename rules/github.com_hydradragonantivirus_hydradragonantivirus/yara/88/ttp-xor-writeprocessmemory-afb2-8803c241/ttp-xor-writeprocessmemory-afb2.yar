rule TTP_XOR_WriteProcessMemory_afb2 {
  strings:
    $key_afb2 = { f8 c0 [2] ca e2 [2] cc d7 [2] e2 d7 [2] dd cb }

  condition:
    any of them
}