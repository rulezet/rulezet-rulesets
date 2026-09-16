rule TTP_XOR_WriteProcessMemory_825f {
  strings:
    $key_825f = { d5 2d [2] e7 0f [2] e1 3a [2] cf 3a [2] f0 26 }

  condition:
    any of them
}