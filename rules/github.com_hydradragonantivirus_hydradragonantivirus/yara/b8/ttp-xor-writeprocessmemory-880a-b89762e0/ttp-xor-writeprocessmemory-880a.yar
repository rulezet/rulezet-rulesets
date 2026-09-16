rule TTP_XOR_WriteProcessMemory_880a {
  strings:
    $key_880a = { df 78 [2] ed 5a [2] eb 6f [2] c5 6f [2] fa 73 }

  condition:
    any of them
}