rule TTP_XOR_WriteProcessMemory_fc39 {
  strings:
    $key_fc39 = { ab 4b [2] 99 69 [2] 9f 5c [2] b1 5c [2] 8e 40 }

  condition:
    any of them
}