rule TTP_XOR_WriteProcessMemory_b6ef {
  strings:
    $key_b6ef = { e1 9d [2] d3 bf [2] d5 8a [2] fb 8a [2] c4 96 }

  condition:
    any of them
}