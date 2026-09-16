rule TTP_XOR_WriteProcessMemory_af2a {
  strings:
    $key_af2a = { f8 58 [2] ca 7a [2] cc 4f [2] e2 4f [2] dd 53 }

  condition:
    any of them
}