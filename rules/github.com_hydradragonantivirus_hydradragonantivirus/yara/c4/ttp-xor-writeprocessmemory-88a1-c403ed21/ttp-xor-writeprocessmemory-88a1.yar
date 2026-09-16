rule TTP_XOR_WriteProcessMemory_88a1 {
  strings:
    $key_88a1 = { df d3 [2] ed f1 [2] eb c4 [2] c5 c4 [2] fa d8 }

  condition:
    any of them
}