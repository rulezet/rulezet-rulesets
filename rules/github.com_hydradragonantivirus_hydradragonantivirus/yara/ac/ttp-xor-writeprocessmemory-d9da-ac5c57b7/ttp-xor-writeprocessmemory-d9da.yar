rule TTP_XOR_WriteProcessMemory_d9da {
  strings:
    $key_d9da = { 8e a8 [2] bc 8a [2] ba bf [2] 94 bf [2] ab a3 }

  condition:
    any of them
}