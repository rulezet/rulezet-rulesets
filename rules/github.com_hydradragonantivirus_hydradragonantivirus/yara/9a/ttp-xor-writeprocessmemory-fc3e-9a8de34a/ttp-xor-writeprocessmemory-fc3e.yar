rule TTP_XOR_WriteProcessMemory_fc3e {
  strings:
    $key_fc3e = { ab 4c [2] 99 6e [2] 9f 5b [2] b1 5b [2] 8e 47 }

  condition:
    any of them
}