rule TTP_XOR_WriteProcessMemory_afdf {
  strings:
    $key_afdf = { f8 ad [2] ca 8f [2] cc ba [2] e2 ba [2] dd a6 }

  condition:
    any of them
}