rule TTP_XOR_WriteProcessMemory_afc6 {
  strings:
    $key_afc6 = { f8 b4 [2] ca 96 [2] cc a3 [2] e2 a3 [2] dd bf }

  condition:
    any of them
}