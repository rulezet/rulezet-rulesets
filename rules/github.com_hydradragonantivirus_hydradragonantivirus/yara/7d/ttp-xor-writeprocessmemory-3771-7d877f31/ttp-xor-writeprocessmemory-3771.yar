rule TTP_XOR_WriteProcessMemory_3771 {
  strings:
    $key_3771 = { 60 03 [2] 52 21 [2] 54 14 [2] 7a 14 [2] 45 08 }

  condition:
    any of them
}