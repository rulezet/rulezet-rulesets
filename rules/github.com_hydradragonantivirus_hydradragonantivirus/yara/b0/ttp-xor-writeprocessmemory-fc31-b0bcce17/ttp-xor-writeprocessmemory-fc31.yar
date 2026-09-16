rule TTP_XOR_WriteProcessMemory_fc31 {
  strings:
    $key_fc31 = { ab 43 [2] 99 61 [2] 9f 54 [2] b1 54 [2] 8e 48 }

  condition:
    any of them
}