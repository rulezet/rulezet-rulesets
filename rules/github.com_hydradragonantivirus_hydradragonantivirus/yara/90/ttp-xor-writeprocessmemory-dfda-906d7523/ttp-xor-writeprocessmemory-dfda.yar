rule TTP_XOR_WriteProcessMemory_dfda {
  strings:
    $key_dfda = { 88 a8 [2] ba 8a [2] bc bf [2] 92 bf [2] ad a3 }

  condition:
    any of them
}