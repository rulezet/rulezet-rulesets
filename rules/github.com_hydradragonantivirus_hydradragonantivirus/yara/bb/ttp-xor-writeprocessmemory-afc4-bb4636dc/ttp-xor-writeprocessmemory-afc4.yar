rule TTP_XOR_WriteProcessMemory_afc4 {
  strings:
    $key_afc4 = { f8 b6 [2] ca 94 [2] cc a1 [2] e2 a1 [2] dd bd }

  condition:
    any of them
}