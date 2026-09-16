rule TTP_XOR_WriteProcessMemory_2d14 {
  strings:
    $key_2d14 = { 7a 66 [2] 48 44 [2] 4e 71 [2] 60 71 [2] 5f 6d }

  condition:
    any of them
}