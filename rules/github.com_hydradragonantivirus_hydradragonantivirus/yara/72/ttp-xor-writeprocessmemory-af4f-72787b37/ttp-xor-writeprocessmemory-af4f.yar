rule TTP_XOR_WriteProcessMemory_af4f {
  strings:
    $key_af4f = { f8 3d [2] ca 1f [2] cc 2a [2] e2 2a [2] dd 36 }

  condition:
    any of them
}