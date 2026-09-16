rule TTP_XOR_WriteProcessMemory_8867 {
  strings:
    $key_8867 = { df 15 [2] ed 37 [2] eb 02 [2] c5 02 [2] fa 1e }

  condition:
    any of them
}