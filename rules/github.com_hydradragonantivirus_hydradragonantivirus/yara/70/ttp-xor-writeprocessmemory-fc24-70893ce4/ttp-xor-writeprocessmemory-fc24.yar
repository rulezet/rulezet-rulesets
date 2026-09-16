rule TTP_XOR_WriteProcessMemory_fc24 {
  strings:
    $key_fc24 = { ab 56 [2] 99 74 [2] 9f 41 [2] b1 41 [2] 8e 5d }

  condition:
    any of them
}