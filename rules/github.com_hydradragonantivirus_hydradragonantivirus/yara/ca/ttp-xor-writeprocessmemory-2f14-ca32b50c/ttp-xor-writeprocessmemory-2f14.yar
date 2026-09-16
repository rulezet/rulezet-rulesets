rule TTP_XOR_WriteProcessMemory_2f14 {
  strings:
    $key_2f14 = { 78 66 [2] 4a 44 [2] 4c 71 [2] 62 71 [2] 5d 6d }

  condition:
    any of them
}