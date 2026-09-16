rule TTP_XOR_WriteProcessMemory_fc09 {
  strings:
    $key_fc09 = { ab 7b [2] 99 59 [2] 9f 6c [2] b1 6c [2] 8e 70 }

  condition:
    any of them
}