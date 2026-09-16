rule TTP_XOR_WriteProcessMemory_fc5a {
  strings:
    $key_fc5a = { ab 28 [2] 99 0a [2] 9f 3f [2] b1 3f [2] 8e 23 }

  condition:
    any of them
}