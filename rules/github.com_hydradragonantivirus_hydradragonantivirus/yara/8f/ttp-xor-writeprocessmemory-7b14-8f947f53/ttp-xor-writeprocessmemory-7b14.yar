rule TTP_XOR_WriteProcessMemory_7b14 {
  strings:
    $key_7b14 = { 2c 66 [2] 1e 44 [2] 18 71 [2] 36 71 [2] 09 6d }

  condition:
    any of them
}