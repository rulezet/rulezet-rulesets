rule TTP_XOR_WriteProcessMemory_5944 {
  strings:
    $key_5944 = { 0e 36 [2] 3c 14 [2] 3a 21 [2] 14 21 [2] 2b 3d }

  condition:
    any of them
}