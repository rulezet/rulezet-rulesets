rule TTP_XOR_WriteProcessMemory_a9cb {
  strings:
    $key_a9cb = { fe b9 [2] cc 9b [2] ca ae [2] e4 ae [2] db b2 }

  condition:
    any of them
}