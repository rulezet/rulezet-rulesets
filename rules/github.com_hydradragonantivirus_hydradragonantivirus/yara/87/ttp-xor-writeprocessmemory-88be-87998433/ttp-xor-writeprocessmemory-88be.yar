rule TTP_XOR_WriteProcessMemory_88be {
  strings:
    $key_88be = { df cc [2] ed ee [2] eb db [2] c5 db [2] fa c7 }

  condition:
    any of them
}