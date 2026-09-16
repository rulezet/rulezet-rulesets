rule TTP_XOR_WriteProcessMemory_88f8 {
  strings:
    $key_88f8 = { df 8a [2] ed a8 [2] eb 9d [2] c5 9d [2] fa 81 }

  condition:
    any of them
}