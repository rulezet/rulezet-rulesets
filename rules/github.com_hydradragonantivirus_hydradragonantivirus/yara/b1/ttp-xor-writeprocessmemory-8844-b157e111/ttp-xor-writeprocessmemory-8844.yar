rule TTP_XOR_WriteProcessMemory_8844 {
  strings:
    $key_8844 = { df 36 [2] ed 14 [2] eb 21 [2] c5 21 [2] fa 3d }

  condition:
    any of them
}