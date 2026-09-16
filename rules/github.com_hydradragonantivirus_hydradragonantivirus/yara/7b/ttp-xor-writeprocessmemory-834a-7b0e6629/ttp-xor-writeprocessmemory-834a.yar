rule TTP_XOR_WriteProcessMemory_834a {
  strings:
    $key_834a = { d4 38 [2] e6 1a [2] e0 2f [2] ce 2f [2] f1 33 }

  condition:
    any of them
}