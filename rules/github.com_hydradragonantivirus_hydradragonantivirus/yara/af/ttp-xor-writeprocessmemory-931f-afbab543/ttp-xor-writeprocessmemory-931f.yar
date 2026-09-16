rule TTP_XOR_WriteProcessMemory_931f {
  strings:
    $key_931f = { c4 6d [2] f6 4f [2] f0 7a [2] de 7a [2] e1 66 }

  condition:
    any of them
}