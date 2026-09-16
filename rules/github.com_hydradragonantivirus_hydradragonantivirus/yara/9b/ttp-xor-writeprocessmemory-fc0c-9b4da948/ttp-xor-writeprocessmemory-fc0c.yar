rule TTP_XOR_WriteProcessMemory_fc0c {
  strings:
    $key_fc0c = { ab 7e [2] 99 5c [2] 9f 69 [2] b1 69 [2] 8e 75 }

  condition:
    any of them
}