rule TTP_XOR_WriteProcessMemory_fc47 {
  strings:
    $key_fc47 = { ab 35 [2] 99 17 [2] 9f 22 [2] b1 22 [2] 8e 3e }

  condition:
    any of them
}