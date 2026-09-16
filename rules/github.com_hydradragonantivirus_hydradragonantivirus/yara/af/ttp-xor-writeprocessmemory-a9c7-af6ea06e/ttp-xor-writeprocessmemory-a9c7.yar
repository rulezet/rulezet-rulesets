rule TTP_XOR_WriteProcessMemory_a9c7 {
  strings:
    $key_a9c7 = { fe b5 [2] cc 97 [2] ca a2 [2] e4 a2 [2] db be }

  condition:
    any of them
}