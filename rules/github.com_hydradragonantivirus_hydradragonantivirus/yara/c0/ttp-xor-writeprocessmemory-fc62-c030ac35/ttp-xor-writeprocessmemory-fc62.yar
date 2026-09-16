rule TTP_XOR_WriteProcessMemory_fc62 {
  strings:
    $key_fc62 = { ab 10 [2] 99 32 [2] 9f 07 [2] b1 07 [2] 8e 1b }

  condition:
    any of them
}