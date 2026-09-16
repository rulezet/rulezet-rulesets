rule TTP_XOR_WriteProcessMemory_aba9 {
  strings:
    $key_aba9 = { fc db [2] ce f9 [2] c8 cc [2] e6 cc [2] d9 d0 }

  condition:
    any of them
}