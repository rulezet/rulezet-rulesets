rule TTP_XOR_WriteProcessMemory_fce1 {
  strings:
    $key_fce1 = { ab 93 [2] 99 b1 [2] 9f 84 [2] b1 84 [2] 8e 98 }

  condition:
    any of them
}