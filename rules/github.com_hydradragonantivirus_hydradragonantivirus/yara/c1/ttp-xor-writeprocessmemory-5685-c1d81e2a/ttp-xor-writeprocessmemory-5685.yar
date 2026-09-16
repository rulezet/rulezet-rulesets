rule TTP_XOR_WriteProcessMemory_5685 {
  strings:
    $key_5685 = { 01 f7 [2] 33 d5 [2] 35 e0 [2] 1b e0 [2] 24 fc }

  condition:
    any of them
}