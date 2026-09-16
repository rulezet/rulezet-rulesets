rule TTP_XOR_WriteProcessMemory_880d {
  strings:
    $key_880d = { df 7f [2] ed 5d [2] eb 68 [2] c5 68 [2] fa 74 }

  condition:
    any of them
}