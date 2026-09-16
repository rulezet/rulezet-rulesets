rule TTP_XOR_WriteProcessMemory_55c5 {
  strings:
    $key_55c5 = { 02 b7 [2] 30 95 [2] 36 a0 [2] 18 a0 [2] 27 bc }

  condition:
    any of them
}