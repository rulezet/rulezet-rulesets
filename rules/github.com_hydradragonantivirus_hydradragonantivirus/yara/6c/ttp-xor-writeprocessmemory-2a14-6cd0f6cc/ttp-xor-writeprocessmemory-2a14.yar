rule TTP_XOR_WriteProcessMemory_2a14 {
  strings:
    $key_2a14 = { 7d 66 [2] 4f 44 [2] 49 71 [2] 67 71 [2] 58 6d }

  condition:
    any of them
}