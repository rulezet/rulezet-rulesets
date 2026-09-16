rule TTP_XOR_WriteProcessMemory_0376 {
  strings:
    $key_0376 = { 54 04 [2] 66 26 [2] 60 13 [2] 4e 13 [2] 71 0f }

  condition:
    any of them
}