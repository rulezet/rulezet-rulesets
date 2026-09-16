rule TTP_XOR_WriteProcessMemory_fc3b {
  strings:
    $key_fc3b = { ab 49 [2] 99 6b [2] 9f 5e [2] b1 5e [2] 8e 42 }

  condition:
    any of them
}