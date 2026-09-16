rule TTP_XOR_WriteProcessMemory_af1f {
  strings:
    $key_af1f = { f8 6d [2] ca 4f [2] cc 7a [2] e2 7a [2] dd 66 }

  condition:
    any of them
}