rule TTP_XOR_WriteProcessMemory_2592 {
  strings:
    $key_2592 = { 72 e0 [2] 40 c2 [2] 46 f7 [2] 68 f7 [2] 57 eb }

  condition:
    any of them
}