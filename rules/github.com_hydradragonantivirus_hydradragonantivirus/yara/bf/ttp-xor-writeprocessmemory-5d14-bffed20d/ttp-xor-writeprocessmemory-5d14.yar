rule TTP_XOR_WriteProcessMemory_5d14 {
  strings:
    $key_5d14 = { 0a 66 [2] 38 44 [2] 3e 71 [2] 10 71 [2] 2f 6d }

  condition:
    any of them
}