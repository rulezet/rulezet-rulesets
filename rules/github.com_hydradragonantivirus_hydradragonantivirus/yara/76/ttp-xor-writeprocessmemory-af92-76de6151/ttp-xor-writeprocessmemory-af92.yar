rule TTP_XOR_WriteProcessMemory_af92 {
  strings:
    $key_af92 = { f8 e0 [2] ca c2 [2] cc f7 [2] e2 f7 [2] dd eb }

  condition:
    any of them
}