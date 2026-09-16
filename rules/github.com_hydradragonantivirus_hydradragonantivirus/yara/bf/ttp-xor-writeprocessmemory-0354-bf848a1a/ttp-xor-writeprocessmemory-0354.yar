rule TTP_XOR_WriteProcessMemory_0354 {
  strings:
    $key_0354 = { 54 26 [2] 66 04 [2] 60 31 [2] 4e 31 [2] 71 2d }

  condition:
    any of them
}