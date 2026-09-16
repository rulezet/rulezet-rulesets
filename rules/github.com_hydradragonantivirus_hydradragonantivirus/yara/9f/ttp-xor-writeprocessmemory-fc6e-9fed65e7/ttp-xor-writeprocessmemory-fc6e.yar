rule TTP_XOR_WriteProcessMemory_fc6e {
  strings:
    $key_fc6e = { ab 1c [2] 99 3e [2] 9f 0b [2] b1 0b [2] 8e 17 }

  condition:
    any of them
}