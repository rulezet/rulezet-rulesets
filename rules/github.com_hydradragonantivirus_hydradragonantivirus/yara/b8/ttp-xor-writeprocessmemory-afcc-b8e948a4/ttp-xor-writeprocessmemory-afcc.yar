rule TTP_XOR_WriteProcessMemory_afcc {
  strings:
    $key_afcc = { f8 be [2] ca 9c [2] cc a9 [2] e2 a9 [2] dd b5 }

  condition:
    any of them
}