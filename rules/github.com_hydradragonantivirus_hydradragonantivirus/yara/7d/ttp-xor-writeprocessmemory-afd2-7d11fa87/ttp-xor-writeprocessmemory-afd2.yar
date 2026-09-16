rule TTP_XOR_WriteProcessMemory_afd2 {
  strings:
    $key_afd2 = { f8 a0 [2] ca 82 [2] cc b7 [2] e2 b7 [2] dd ab }

  condition:
    any of them
}