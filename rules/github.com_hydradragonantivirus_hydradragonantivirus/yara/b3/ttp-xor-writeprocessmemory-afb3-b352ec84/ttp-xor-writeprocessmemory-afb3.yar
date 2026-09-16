rule TTP_XOR_WriteProcessMemory_afb3 {
  strings:
    $key_afb3 = { f8 c1 [2] ca e3 [2] cc d6 [2] e2 d6 [2] dd ca }

  condition:
    any of them
}