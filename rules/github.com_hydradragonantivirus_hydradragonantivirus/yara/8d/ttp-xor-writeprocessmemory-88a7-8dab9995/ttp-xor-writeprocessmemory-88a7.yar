rule TTP_XOR_WriteProcessMemory_88a7 {
  strings:
    $key_88a7 = { df d5 [2] ed f7 [2] eb c2 [2] c5 c2 [2] fa de }

  condition:
    any of them
}