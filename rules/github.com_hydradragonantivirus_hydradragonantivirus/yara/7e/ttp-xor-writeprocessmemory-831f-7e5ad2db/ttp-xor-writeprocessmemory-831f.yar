rule TTP_XOR_WriteProcessMemory_831f {
  strings:
    $key_831f = { d4 6d [2] e6 4f [2] e0 7a [2] ce 7a [2] f1 66 }

  condition:
    any of them
}