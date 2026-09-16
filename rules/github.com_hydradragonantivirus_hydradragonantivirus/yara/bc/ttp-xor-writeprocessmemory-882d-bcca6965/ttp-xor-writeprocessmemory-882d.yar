rule TTP_XOR_WriteProcessMemory_882d {
  strings:
    $key_882d = { df 5f [2] ed 7d [2] eb 48 [2] c5 48 [2] fa 54 }

  condition:
    any of them
}