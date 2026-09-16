rule TTP_XOR_WriteProcessMemory_66c5 {
  strings:
    $key_66c5 = { 31 b7 [2] 03 95 [2] 05 a0 [2] 2b a0 [2] 14 bc }

  condition:
    any of them
}