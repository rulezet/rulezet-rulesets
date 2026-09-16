rule TTP_XOR_WriteProcessMemory_03f7 {
  strings:
    $key_03f7 = { 54 85 [2] 66 a7 [2] 60 92 [2] 4e 92 [2] 71 8e }

  condition:
    any of them
}