rule TTP_XOR_WriteProcessMemory_afcd {
  strings:
    $key_afcd = { f8 bf [2] ca 9d [2] cc a8 [2] e2 a8 [2] dd b4 }

  condition:
    any of them
}