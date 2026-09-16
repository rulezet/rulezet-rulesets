rule TTP_XOR_WriteProcessMemory_fc7a {
  strings:
    $key_fc7a = { ab 08 [2] 99 2a [2] 9f 1f [2] b1 1f [2] 8e 03 }

  condition:
    any of them
}