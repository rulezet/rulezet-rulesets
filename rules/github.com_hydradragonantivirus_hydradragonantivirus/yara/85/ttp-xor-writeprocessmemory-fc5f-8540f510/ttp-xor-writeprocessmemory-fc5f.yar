rule TTP_XOR_WriteProcessMemory_fc5f {
  strings:
    $key_fc5f = { ab 2d [2] 99 0f [2] 9f 3a [2] b1 3a [2] 8e 26 }

  condition:
    any of them
}