rule TTP_XOR_WriteProcessMemory_88f4 {
  strings:
    $key_88f4 = { df 86 [2] ed a4 [2] eb 91 [2] c5 91 [2] fa 8d }

  condition:
    any of them
}