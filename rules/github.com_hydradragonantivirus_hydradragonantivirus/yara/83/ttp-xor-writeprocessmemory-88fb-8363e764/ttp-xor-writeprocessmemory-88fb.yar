rule TTP_XOR_WriteProcessMemory_88fb {
  strings:
    $key_88fb = { df 89 [2] ed ab [2] eb 9e [2] c5 9e [2] fa 82 }

  condition:
    any of them
}