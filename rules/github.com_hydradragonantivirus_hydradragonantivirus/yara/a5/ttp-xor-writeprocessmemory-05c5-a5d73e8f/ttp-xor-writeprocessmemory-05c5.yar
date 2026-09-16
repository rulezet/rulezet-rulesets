rule TTP_XOR_WriteProcessMemory_05c5 {
  strings:
    $key_05c5 = { 52 b7 [2] 60 95 [2] 66 a0 [2] 48 a0 [2] 77 bc }

  condition:
    any of them
}