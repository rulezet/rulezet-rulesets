rule TTP_XOR_WriteProcessMemory_fc29 {
  strings:
    $key_fc29 = { ab 5b [2] 99 79 [2] 9f 4c [2] b1 4c [2] 8e 50 }

  condition:
    any of them
}