rule TTP_XOR_WriteProcessMemory_af82 {
  strings:
    $key_af82 = { f8 f0 [2] ca d2 [2] cc e7 [2] e2 e7 [2] dd fb }

  condition:
    any of them
}