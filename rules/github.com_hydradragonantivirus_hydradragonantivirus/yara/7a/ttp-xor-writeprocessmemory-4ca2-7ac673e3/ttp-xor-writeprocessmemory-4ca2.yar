rule TTP_XOR_WriteProcessMemory_4ca2 {
  strings:
    $key_4ca2 = { 1b d0 [2] 29 f2 [2] 2f c7 [2] 01 c7 [2] 3e db }

  condition:
    any of them
}