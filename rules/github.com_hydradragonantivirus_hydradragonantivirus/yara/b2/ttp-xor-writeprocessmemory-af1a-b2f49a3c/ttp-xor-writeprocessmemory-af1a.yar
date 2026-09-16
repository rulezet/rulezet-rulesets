rule TTP_XOR_WriteProcessMemory_af1a {
  strings:
    $key_af1a = { f8 68 [2] ca 4a [2] cc 7f [2] e2 7f [2] dd 63 }

  condition:
    any of them
}