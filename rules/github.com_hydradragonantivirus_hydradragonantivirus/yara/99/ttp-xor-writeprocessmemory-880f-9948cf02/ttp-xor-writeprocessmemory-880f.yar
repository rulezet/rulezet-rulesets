rule TTP_XOR_WriteProcessMemory_880f {
  strings:
    $key_880f = { df 7d [2] ed 5f [2] eb 6a [2] c5 6a [2] fa 76 }

  condition:
    any of them
}