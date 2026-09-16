rule TTP_XOR_WriteProcessMemory_8eef {
  strings:
    $key_8eef = { d9 9d [2] eb bf [2] ed 8a [2] c3 8a [2] fc 96 }

  condition:
    any of them
}