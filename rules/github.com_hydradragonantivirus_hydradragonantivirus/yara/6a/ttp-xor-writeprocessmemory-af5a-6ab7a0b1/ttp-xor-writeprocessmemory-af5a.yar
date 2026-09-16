rule TTP_XOR_WriteProcessMemory_af5a {
  strings:
    $key_af5a = { f8 28 [2] ca 0a [2] cc 3f [2] e2 3f [2] dd 23 }

  condition:
    any of them
}