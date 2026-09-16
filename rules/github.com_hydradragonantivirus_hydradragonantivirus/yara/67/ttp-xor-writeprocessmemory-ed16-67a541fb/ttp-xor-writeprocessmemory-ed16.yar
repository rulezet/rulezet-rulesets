rule TTP_XOR_WriteProcessMemory_ed16 {
  strings:
    $key_ed16 = { ba 64 [2] 88 46 [2] 8e 73 [2] a0 73 [2] 9f 6f }

  condition:
    any of them
}