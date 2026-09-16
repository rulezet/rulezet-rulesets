rule TTP_XOR_WriteProcessMemory_4d14 {
  strings:
    $key_4d14 = { 1a 66 [2] 28 44 [2] 2e 71 [2] 00 71 [2] 3f 6d }

  condition:
    any of them
}