rule TTP_XOR_WriteProcessMemory_830a {
  strings:
    $key_830a = { d4 78 [2] e6 5a [2] e0 6f [2] ce 6f [2] f1 73 }

  condition:
    any of them
}