rule TTP_XOR_WriteProcessMemory_fc92 {
  strings:
    $key_fc92 = { ab e0 [2] 99 c2 [2] 9f f7 [2] b1 f7 [2] 8e eb }

  condition:
    any of them
}