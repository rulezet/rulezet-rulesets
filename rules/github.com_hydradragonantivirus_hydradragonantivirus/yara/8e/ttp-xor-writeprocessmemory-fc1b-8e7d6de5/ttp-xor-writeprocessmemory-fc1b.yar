rule TTP_XOR_WriteProcessMemory_fc1b {
  strings:
    $key_fc1b = { ab 69 [2] 99 4b [2] 9f 7e [2] b1 7e [2] 8e 62 }

  condition:
    any of them
}