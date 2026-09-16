rule TTP_XOR_WriteProcessMemory_884a {
  strings:
    $key_884a = { df 38 [2] ed 1a [2] eb 2f [2] c5 2f [2] fa 33 }

  condition:
    any of them
}