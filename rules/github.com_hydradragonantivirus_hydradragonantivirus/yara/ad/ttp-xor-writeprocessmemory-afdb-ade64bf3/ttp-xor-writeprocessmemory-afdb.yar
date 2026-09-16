rule TTP_XOR_WriteProcessMemory_afdb {
  strings:
    $key_afdb = { f8 a9 [2] ca 8b [2] cc be [2] e2 be [2] dd a2 }

  condition:
    any of them
}