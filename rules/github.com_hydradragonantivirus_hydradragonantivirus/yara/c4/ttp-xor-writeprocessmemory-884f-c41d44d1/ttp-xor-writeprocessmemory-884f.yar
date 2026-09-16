rule TTP_XOR_WriteProcessMemory_884f {
  strings:
    $key_884f = { df 3d [2] ed 1f [2] eb 2a [2] c5 2a [2] fa 36 }

  condition:
    any of them
}