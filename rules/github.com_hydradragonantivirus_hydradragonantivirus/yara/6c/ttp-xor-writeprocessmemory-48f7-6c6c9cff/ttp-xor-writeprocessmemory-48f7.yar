rule TTP_XOR_WriteProcessMemory_48f7 {
  strings:
    $key_48f7 = { 1f 85 [2] 2d a7 [2] 2b 92 [2] 05 92 [2] 3a 8e }

  condition:
    any of them
}