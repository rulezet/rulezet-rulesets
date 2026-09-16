rule TTP_XOR_WriteProcessMemory_0492 {
  strings:
    $key_0492 = { 53 e0 [2] 61 c2 [2] 67 f7 [2] 49 f7 [2] 76 eb }

  condition:
    any of them
}