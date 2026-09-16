rule TTP_XOR_WriteProcessMemory_fc1a {
  strings:
    $key_fc1a = { ab 68 [2] 99 4a [2] 9f 7f [2] b1 7f [2] 8e 63 }

  condition:
    any of them
}