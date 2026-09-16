rule TTP_XOR_WriteProcessMemory_edf6 {
  strings:
    $key_edf6 = { ba 84 [2] 88 a6 [2] 8e 93 [2] a0 93 [2] 9f 8f }

  condition:
    any of them
}