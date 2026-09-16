rule TTP_XOR_WriteProcessMemory_e17f {
  strings:
    $key_e17f = { b6 0d [2] 84 2f [2] 82 1a [2] ac 1a [2] 93 06 }

  condition:
    any of them
}