rule TTP_XOR_WriteProcessMemory_dfcd {
  strings:
    $key_dfcd = { 88 bf [2] ba 9d [2] bc a8 [2] 92 a8 [2] ad b4 }

  condition:
    any of them
}