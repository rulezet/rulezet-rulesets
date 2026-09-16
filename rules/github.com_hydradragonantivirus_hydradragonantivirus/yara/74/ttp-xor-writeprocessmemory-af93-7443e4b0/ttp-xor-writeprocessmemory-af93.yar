rule TTP_XOR_WriteProcessMemory_af93 {
  strings:
    $key_af93 = { f8 e1 [2] ca c3 [2] cc f6 [2] e2 f6 [2] dd ea }

  condition:
    any of them
}