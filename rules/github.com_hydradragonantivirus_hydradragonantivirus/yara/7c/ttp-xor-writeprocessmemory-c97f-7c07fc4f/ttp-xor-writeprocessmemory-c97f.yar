rule TTP_XOR_WriteProcessMemory_c97f {
  strings:
    $key_c97f = { 9e 0d [2] ac 2f [2] aa 1a [2] 84 1a [2] bb 06 }

  condition:
    any of them
}