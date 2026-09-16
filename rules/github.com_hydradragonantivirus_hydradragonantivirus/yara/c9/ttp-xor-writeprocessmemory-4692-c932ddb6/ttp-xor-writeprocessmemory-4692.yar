rule TTP_XOR_WriteProcessMemory_4692 {
  strings:
    $key_4692 = { 11 e0 [2] 23 c2 [2] 25 f7 [2] 0b f7 [2] 34 eb }

  condition:
    any of them
}