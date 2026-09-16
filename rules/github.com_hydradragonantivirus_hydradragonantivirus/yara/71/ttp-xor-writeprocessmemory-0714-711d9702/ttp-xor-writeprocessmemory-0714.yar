rule TTP_XOR_WriteProcessMemory_0714 {
  strings:
    $key_0714 = { 50 66 [2] 62 44 [2] 64 71 [2] 4a 71 [2] 75 6d }

  condition:
    any of them
}