rule TTP_XOR_WriteProcessMemory_874f {
  strings:
    $key_874f = { d0 3d [2] e2 1f [2] e4 2a [2] ca 2a [2] f5 36 }

  condition:
    any of them
}