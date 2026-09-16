rule TTP_XOR_WriteProcessMemory_88a6 {
  strings:
    $key_88a6 = { df d4 [2] ed f6 [2] eb c3 [2] c5 c3 [2] fa df }

  condition:
    any of them
}