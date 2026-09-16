rule TTP_XOR_WriteProcessMemory_8857 {
  strings:
    $key_8857 = { df 25 [2] ed 07 [2] eb 32 [2] c5 32 [2] fa 2e }

  condition:
    any of them
}