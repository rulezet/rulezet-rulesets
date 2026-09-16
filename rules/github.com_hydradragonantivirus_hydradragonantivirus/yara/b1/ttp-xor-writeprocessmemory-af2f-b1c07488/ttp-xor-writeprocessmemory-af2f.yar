rule TTP_XOR_WriteProcessMemory_af2f {
  strings:
    $key_af2f = { f8 5d [2] ca 7f [2] cc 4a [2] e2 4a [2] dd 56 }

  condition:
    any of them
}