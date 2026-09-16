rule TTP_XOR_WriteProcessMemory_5371 {
  strings:
    $key_5371 = { 04 03 [2] 36 21 [2] 30 14 [2] 1e 14 [2] 21 08 }

  condition:
    any of them
}