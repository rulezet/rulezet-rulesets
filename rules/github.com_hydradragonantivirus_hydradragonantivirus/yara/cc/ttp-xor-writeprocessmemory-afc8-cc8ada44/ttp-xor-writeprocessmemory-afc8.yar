rule TTP_XOR_WriteProcessMemory_afc8 {
  strings:
    $key_afc8 = { f8 ba [2] ca 98 [2] cc ad [2] e2 ad [2] dd b1 }

  condition:
    any of them
}