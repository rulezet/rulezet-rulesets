rule TTP_XOR_WriteProcessMemory_fc4a {
  strings:
    $key_fc4a = { ab 38 [2] 99 1a [2] 9f 2f [2] b1 2f [2] 8e 33 }

  condition:
    any of them
}