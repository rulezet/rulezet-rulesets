rule TTP_XOR_WriteProcessMemory_fc19 {
  strings:
    $key_fc19 = { ab 6b [2] 99 49 [2] 9f 7c [2] b1 7c [2] 8e 60 }

  condition:
    any of them
}