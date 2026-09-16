rule TTP_XOR_WriteProcessMemory_1692 {
  strings:
    $key_1692 = { 41 e0 [2] 73 c2 [2] 75 f7 [2] 5b f7 [2] 64 eb }

  condition:
    any of them
}