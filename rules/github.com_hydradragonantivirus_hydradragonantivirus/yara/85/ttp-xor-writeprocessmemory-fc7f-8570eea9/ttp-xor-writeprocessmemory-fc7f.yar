rule TTP_XOR_WriteProcessMemory_fc7f {
  strings:
    $key_fc7f = { ab 0d [2] 99 2f [2] 9f 1a [2] b1 1a [2] 8e 06 }

  condition:
    any of them
}