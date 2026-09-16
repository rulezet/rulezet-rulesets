rule TTP_XOR_WriteProcessMemory_8852 {
  strings:
    $key_8852 = { df 20 [2] ed 02 [2] eb 37 [2] c5 37 [2] fa 2b }

  condition:
    any of them
}