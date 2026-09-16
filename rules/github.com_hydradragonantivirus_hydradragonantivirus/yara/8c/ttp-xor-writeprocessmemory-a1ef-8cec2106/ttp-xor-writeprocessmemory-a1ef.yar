rule TTP_XOR_WriteProcessMemory_a1ef {
  strings:
    $key_a1ef = { f6 9d [2] c4 bf [2] c2 8a [2] ec 8a [2] d3 96 }

  condition:
    any of them
}