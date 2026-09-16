rule TTP_XOR_WriteProcessMemory_efef {
  strings:
    $key_efef = { b8 9d [2] 8a bf [2] 8c 8a [2] a2 8a [2] 9d 96 }

  condition:
    any of them
}