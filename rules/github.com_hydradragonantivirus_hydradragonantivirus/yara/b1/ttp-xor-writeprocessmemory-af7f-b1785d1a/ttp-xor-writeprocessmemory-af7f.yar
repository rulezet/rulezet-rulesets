rule TTP_XOR_WriteProcessMemory_af7f {
  strings:
    $key_af7f = { f8 0d [2] ca 2f [2] cc 1a [2] e2 1a [2] dd 06 }

  condition:
    any of them
}