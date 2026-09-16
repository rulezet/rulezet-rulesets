rule TTP_XOR_WriteProcessMemory_afb7 {
  strings:
    $key_afb7 = { f8 c5 [2] ca e7 [2] cc d2 [2] e2 d2 [2] dd ce }

  condition:
    any of them
}