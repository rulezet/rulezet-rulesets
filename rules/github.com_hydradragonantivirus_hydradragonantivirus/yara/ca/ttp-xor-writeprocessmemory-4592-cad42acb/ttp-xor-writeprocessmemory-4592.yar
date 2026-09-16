rule TTP_XOR_WriteProcessMemory_4592 {
  strings:
    $key_4592 = { 12 e0 [2] 20 c2 [2] 26 f7 [2] 08 f7 [2] 37 eb }

  condition:
    any of them
}