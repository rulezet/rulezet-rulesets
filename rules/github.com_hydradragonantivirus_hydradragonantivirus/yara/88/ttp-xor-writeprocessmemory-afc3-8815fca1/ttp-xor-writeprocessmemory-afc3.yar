rule TTP_XOR_WriteProcessMemory_afc3 {
  strings:
    $key_afc3 = { f8 b1 [2] ca 93 [2] cc a6 [2] e2 a6 [2] dd ba }

  condition:
    any of them
}