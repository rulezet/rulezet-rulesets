rule TTP_XOR_WriteProcessMemory_7e42 {
  strings:
    $key_7e42 = { 29 30 [2] 1b 12 [2] 1d 27 [2] 33 27 [2] 0c 3b }

  condition:
    any of them
}