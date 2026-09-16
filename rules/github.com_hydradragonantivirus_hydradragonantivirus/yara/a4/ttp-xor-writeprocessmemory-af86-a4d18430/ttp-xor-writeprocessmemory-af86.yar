rule TTP_XOR_WriteProcessMemory_af86 {
  strings:
    $key_af86 = { f8 f4 [2] ca d6 [2] cc e3 [2] e2 e3 [2] dd ff }

  condition:
    any of them
}