rule TTP_XOR_WriteProcessMemory_afb5 {
  strings:
    $key_afb5 = { f8 c7 [2] ca e5 [2] cc d0 [2] e2 d0 [2] dd cc }

  condition:
    any of them
}