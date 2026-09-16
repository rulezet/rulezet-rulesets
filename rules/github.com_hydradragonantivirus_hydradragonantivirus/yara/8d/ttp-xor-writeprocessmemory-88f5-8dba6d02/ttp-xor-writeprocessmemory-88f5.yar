rule TTP_XOR_WriteProcessMemory_88f5 {
  strings:
    $key_88f5 = { df 87 [2] ed a5 [2] eb 90 [2] c5 90 [2] fa 8c }

  condition:
    any of them
}