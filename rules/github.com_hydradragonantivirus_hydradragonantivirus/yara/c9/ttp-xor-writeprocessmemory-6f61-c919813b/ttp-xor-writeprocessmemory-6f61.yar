rule TTP_XOR_WriteProcessMemory_6f61 {
  strings:
    $key_6f61 = { 38 13 [2] 0a 31 [2] 0c 04 [2] 22 04 [2] 1d 18 }

  condition:
    any of them
}