rule TTP_XOR_WriteProcessMemory_885d {
  strings:
    $key_885d = { df 2f [2] ed 0d [2] eb 38 [2] c5 38 [2] fa 24 }

  condition:
    any of them
}