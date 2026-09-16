rule TTP_XOR_WriteProcessMemory_81ff {
  strings:
    $key_81ff = { d6 8d [2] e4 af [2] e2 9a [2] cc 9a [2] f3 86 }

  condition:
    any of them
}