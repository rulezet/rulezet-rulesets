rule TTP_XOR_WriteProcessMemory_acef {
  strings:
    $key_acef = { fb 9d [2] c9 bf [2] cf 8a [2] e1 8a [2] de 96 }

  condition:
    any of them
}