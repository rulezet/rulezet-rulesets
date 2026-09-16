rule TTP_XOR_WriteProcessMemory_fc77 {
  strings:
    $key_fc77 = { ab 05 [2] 99 27 [2] 9f 12 [2] b1 12 [2] 8e 0e }

  condition:
    any of them
}