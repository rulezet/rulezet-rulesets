rule TTP_XOR_WriteProcessMemory_03e4 {
  strings:
    $key_03e4 = { 54 96 [2] 66 b4 [2] 60 81 [2] 4e 81 [2] 71 9d }

  condition:
    any of them
}