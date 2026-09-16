rule TTP_XOR_WriteProcessMemory_cc9c {
  strings:
    $key_cc9c = { 9b ee [2] a9 cc [2] af f9 [2] 81 f9 [2] be e5 }

  condition:
    any of them
}