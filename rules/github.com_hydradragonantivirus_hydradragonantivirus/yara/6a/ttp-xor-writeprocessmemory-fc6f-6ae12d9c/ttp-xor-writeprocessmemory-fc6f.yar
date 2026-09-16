rule TTP_XOR_WriteProcessMemory_fc6f {
  strings:
    $key_fc6f = { ab 1d [2] 99 3f [2] 9f 0a [2] b1 0a [2] 8e 16 }

  condition:
    any of them
}