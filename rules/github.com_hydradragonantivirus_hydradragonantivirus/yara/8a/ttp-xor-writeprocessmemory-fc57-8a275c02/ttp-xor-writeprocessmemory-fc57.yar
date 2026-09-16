rule TTP_XOR_WriteProcessMemory_fc57 {
  strings:
    $key_fc57 = { ab 25 [2] 99 07 [2] 9f 32 [2] b1 32 [2] 8e 2e }

  condition:
    any of them
}