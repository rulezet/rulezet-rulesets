rule TTP_XOR_WriteProcessMemory_88f2 {
  strings:
    $key_88f2 = { df 80 [2] ed a2 [2] eb 97 [2] c5 97 [2] fa 8b }

  condition:
    any of them
}