rule TTP_XOR_WriteProcessMemory_6ca2 {
  strings:
    $key_6ca2 = { 3b d0 [2] 09 f2 [2] 0f c7 [2] 21 c7 [2] 1e db }

  condition:
    any of them
}