rule TTP_XOR_WriteProcessMemory_8859 {
  strings:
    $key_8859 = { df 2b [2] ed 09 [2] eb 3c [2] c5 3c [2] fa 20 }

  condition:
    any of them
}