rule TTP_XOR_WriteProcessMemory_8848 {
  strings:
    $key_8848 = { df 3a [2] ed 18 [2] eb 2d [2] c5 2d [2] fa 31 }

  condition:
    any of them
}