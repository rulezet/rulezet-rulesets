rule TTP_XOR_WriteProcessMemory_88d8 {
  strings:
    $key_88d8 = { df aa [2] ed 88 [2] eb bd [2] c5 bd [2] fa a1 }

  condition:
    any of them
}