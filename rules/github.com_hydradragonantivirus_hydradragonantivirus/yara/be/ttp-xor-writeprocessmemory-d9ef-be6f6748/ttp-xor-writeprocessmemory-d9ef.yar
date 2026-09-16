rule TTP_XOR_WriteProcessMemory_d9ef {
  strings:
    $key_d9ef = { 8e 9d [2] bc bf [2] ba 8a [2] 94 8a [2] ab 96 }

  condition:
    any of them
}