rule TTP_XOR_WriteProcessMemory_affe {
  strings:
    $key_affe = { f8 8c [2] ca ae [2] cc 9b [2] e2 9b [2] dd 87 }

  condition:
    any of them
}