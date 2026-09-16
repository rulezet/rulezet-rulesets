rule TTP_XOR_WriteProcessMemory_810a {
  strings:
    $key_810a = { d6 78 [2] e4 5a [2] e2 6f [2] cc 6f [2] f3 73 }

  condition:
    any of them
}