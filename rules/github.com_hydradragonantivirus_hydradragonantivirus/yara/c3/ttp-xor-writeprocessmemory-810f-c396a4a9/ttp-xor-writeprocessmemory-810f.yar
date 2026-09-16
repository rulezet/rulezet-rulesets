rule TTP_XOR_WriteProcessMemory_810f {
  strings:
    $key_810f = { d6 7d [2] e4 5f [2] e2 6a [2] cc 6a [2] f3 76 }

  condition:
    any of them
}