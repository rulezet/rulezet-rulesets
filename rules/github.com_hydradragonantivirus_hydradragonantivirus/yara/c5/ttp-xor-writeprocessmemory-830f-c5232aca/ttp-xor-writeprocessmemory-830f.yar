rule TTP_XOR_WriteProcessMemory_830f {
  strings:
    $key_830f = { d4 7d [2] e6 5f [2] e0 6a [2] ce 6a [2] f1 76 }

  condition:
    any of them
}