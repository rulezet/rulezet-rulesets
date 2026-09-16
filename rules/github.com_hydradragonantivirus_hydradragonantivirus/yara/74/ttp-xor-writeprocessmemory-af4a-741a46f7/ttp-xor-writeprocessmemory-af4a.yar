rule TTP_XOR_WriteProcessMemory_af4a {
  strings:
    $key_af4a = { f8 38 [2] ca 1a [2] cc 2f [2] e2 2f [2] dd 33 }

  condition:
    any of them
}