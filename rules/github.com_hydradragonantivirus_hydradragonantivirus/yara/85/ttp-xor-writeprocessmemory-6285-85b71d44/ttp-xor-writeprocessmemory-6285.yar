rule TTP_XOR_WriteProcessMemory_6285 {
  strings:
    $key_6285 = { 35 f7 [2] 07 d5 [2] 01 e0 [2] 2f e0 [2] 10 fc }

  condition:
    any of them
}