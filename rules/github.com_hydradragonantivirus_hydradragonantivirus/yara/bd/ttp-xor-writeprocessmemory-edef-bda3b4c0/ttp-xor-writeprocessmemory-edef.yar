rule TTP_XOR_WriteProcessMemory_edef {
  strings:
    $key_edef = { ba 9d [2] 88 bf [2] 8e 8a [2] a0 8a [2] 9f 96 }

  condition:
    any of them
}