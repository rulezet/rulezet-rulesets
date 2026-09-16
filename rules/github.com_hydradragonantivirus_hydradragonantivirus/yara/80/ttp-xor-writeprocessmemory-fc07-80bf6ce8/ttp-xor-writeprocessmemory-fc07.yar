rule TTP_XOR_WriteProcessMemory_fc07 {
  strings:
    $key_fc07 = { ab 75 [2] 99 57 [2] 9f 62 [2] b1 62 [2] 8e 7e }

  condition:
    any of them
}