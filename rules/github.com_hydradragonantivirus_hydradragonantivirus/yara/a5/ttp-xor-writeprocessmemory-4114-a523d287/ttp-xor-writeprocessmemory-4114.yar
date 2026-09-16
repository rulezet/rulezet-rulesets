rule TTP_XOR_WriteProcessMemory_4114 {
  strings:
    $key_4114 = { 16 66 [2] 24 44 [2] 22 71 [2] 0c 71 [2] 33 6d }

  condition:
    any of them
}