rule TTP_XOR_WriteProcessMemory_aada {
  strings:
    $key_aada = { fd a8 [2] cf 8a [2] c9 bf [2] e7 bf [2] d8 a3 }

  condition:
    any of them
}