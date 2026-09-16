rule TTP_XOR_WriteProcessMemory_44c5 {
  strings:
    $key_44c5 = { 13 b7 [2] 21 95 [2] 27 a0 [2] 09 a0 [2] 36 bc }

  condition:
    any of them
}