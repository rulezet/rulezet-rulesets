rule TTP_XOR_WriteProcessMemory_88f7 {
  strings:
    $key_88f7 = { df 85 [2] ed a7 [2] eb 92 [2] c5 92 [2] fa 8e }

  condition:
    any of them
}