rule TTP_XOR_WriteProcessMemory_fc74 {
  strings:
    $key_fc74 = { ab 06 [2] 99 24 [2] 9f 11 [2] b1 11 [2] 8e 0d }

  condition:
    any of them
}