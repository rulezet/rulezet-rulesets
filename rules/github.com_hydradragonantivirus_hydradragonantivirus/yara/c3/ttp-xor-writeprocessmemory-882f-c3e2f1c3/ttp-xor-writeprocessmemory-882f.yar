rule TTP_XOR_WriteProcessMemory_882f {
  strings:
    $key_882f = { df 5d [2] ed 7f [2] eb 4a [2] c5 4a [2] fa 56 }

  condition:
    any of them
}