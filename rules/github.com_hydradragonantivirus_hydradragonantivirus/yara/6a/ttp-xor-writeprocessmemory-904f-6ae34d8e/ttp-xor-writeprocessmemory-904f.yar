rule TTP_XOR_WriteProcessMemory_904f {
  strings:
    $key_904f = { c7 3d [2] f5 1f [2] f3 2a [2] dd 2a [2] e2 36 }

  condition:
    any of them
}