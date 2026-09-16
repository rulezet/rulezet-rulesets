rule TTP_XOR_WriteProcessMemory_fc2b {
  strings:
    $key_fc2b = { ab 59 [2] 99 7b [2] 9f 4e [2] b1 4e [2] 8e 52 }

  condition:
    any of them
}