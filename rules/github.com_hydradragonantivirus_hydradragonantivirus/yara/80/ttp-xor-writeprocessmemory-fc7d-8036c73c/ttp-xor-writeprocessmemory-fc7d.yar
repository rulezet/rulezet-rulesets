rule TTP_XOR_WriteProcessMemory_fc7d {
  strings:
    $key_fc7d = { ab 0f [2] 99 2d [2] 9f 18 [2] b1 18 [2] 8e 04 }

  condition:
    any of them
}