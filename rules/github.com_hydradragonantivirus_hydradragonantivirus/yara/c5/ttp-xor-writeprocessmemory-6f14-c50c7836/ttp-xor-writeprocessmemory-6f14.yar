rule TTP_XOR_WriteProcessMemory_6f14 {
  strings:
    $key_6f14 = { 38 66 [2] 0a 44 [2] 0c 71 [2] 22 71 [2] 1d 6d }

  condition:
    any of them
}