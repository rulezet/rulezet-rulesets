rule TTP_XOR_WriteProcessMemory_fc0b {
  strings:
    $key_fc0b = { ab 79 [2] 99 5b [2] 9f 6e [2] b1 6e [2] 8e 72 }

  condition:
    any of them
}