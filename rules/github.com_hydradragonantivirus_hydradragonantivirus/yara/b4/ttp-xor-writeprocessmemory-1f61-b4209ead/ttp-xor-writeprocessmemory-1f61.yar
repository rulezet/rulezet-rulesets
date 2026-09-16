rule TTP_XOR_WriteProcessMemory_1f61 {
  strings:
    $key_1f61 = { 48 13 [2] 7a 31 [2] 7c 04 [2] 52 04 [2] 6d 18 }

  condition:
    any of them
}