rule TTP_XOR_WriteProcessMemory_a9ca {
  strings:
    $key_a9ca = { fe b8 [2] cc 9a [2] ca af [2] e4 af [2] db b3 }

  condition:
    any of them
}