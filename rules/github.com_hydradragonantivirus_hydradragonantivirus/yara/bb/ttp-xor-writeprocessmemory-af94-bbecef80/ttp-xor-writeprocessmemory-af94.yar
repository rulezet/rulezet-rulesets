rule TTP_XOR_WriteProcessMemory_af94 {
  strings:
    $key_af94 = { f8 e6 [2] ca c4 [2] cc f1 [2] e2 f1 [2] dd ed }

  condition:
    any of them
}