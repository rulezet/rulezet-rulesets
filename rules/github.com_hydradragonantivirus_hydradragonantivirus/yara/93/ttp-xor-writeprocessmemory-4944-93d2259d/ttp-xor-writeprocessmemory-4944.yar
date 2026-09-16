rule TTP_XOR_WriteProcessMemory_4944 {
  strings:
    $key_4944 = { 1e 36 [2] 2c 14 [2] 2a 21 [2] 04 21 [2] 3b 3d }

  condition:
    any of them
}