rule TTP_XOR_WriteProcessMemory_fc45 {
  strings:
    $key_fc45 = { ab 37 [2] 99 15 [2] 9f 20 [2] b1 20 [2] 8e 3c }

  condition:
    any of them
}