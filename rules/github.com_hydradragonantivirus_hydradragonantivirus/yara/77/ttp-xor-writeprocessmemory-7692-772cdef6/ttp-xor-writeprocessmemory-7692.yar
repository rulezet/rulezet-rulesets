rule TTP_XOR_WriteProcessMemory_7692 {
  strings:
    $key_7692 = { 21 e0 [2] 13 c2 [2] 15 f7 [2] 3b f7 [2] 04 eb }

  condition:
    any of them
}