rule TTP_XOR_WriteProcessMemory_fc7c {
  strings:
    $key_fc7c = { ab 0e [2] 99 2c [2] 9f 19 [2] b1 19 [2] 8e 05 }

  condition:
    any of them
}