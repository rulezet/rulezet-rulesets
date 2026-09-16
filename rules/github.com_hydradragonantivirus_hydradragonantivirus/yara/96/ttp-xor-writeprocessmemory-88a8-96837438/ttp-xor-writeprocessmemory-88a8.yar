rule TTP_XOR_WriteProcessMemory_88a8 {
  strings:
    $key_88a8 = { df da [2] ed f8 [2] eb cd [2] c5 cd [2] fa d1 }

  condition:
    any of them
}