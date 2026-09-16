rule TTP_XOR_WriteProcessMemory_0ca2 {
  strings:
    $key_0ca2 = { 5b d0 [2] 69 f2 [2] 6f c7 [2] 41 c7 [2] 7e db }

  condition:
    any of them
}