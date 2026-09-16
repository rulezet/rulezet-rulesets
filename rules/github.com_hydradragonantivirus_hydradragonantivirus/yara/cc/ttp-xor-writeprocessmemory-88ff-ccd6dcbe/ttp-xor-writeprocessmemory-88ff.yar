rule TTP_XOR_WriteProcessMemory_88ff {
  strings:
    $key_88ff = { df 8d [2] ed af [2] eb 9a [2] c5 9a [2] fa 86 }

  condition:
    any of them
}