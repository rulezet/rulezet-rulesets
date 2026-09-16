rule TTP_XOR_WriteProcessMemory_882a {
  strings:
    $key_882a = { df 58 [2] ed 7a [2] eb 4f [2] c5 4f [2] fa 53 }

  condition:
    any of them
}