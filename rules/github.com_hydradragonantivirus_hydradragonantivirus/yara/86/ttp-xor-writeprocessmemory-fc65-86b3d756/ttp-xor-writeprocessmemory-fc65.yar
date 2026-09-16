rule TTP_XOR_WriteProcessMemory_fc65 {
  strings:
    $key_fc65 = { ab 17 [2] 99 35 [2] 9f 00 [2] b1 00 [2] 8e 1c }

  condition:
    any of them
}