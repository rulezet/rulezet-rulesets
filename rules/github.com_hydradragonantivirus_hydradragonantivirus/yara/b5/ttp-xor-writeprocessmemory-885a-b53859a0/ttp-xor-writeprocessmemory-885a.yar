rule TTP_XOR_WriteProcessMemory_885a {
  strings:
    $key_885a = { df 28 [2] ed 0a [2] eb 3f [2] c5 3f [2] fa 23 }

  condition:
    any of them
}