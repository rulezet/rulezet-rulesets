rule TTP_XOR_WriteProcessMemory_8def {
  strings:
    $key_8def = { da 9d [2] e8 bf [2] ee 8a [2] c0 8a [2] ff 96 }

  condition:
    any of them
}