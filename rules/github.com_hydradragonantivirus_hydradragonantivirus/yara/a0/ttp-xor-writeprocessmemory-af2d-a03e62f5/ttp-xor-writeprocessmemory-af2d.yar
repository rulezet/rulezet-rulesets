rule TTP_XOR_WriteProcessMemory_af2d {
  strings:
    $key_af2d = { f8 5f [2] ca 7d [2] cc 48 [2] e2 48 [2] dd 54 }

  condition:
    any of them
}