rule TTP_XOR_WriteProcessMemory_1d61 {
  strings:
    $key_1d61 = { 4a 13 [2] 78 31 [2] 7e 04 [2] 50 04 [2] 6f 18 }

  condition:
    any of them
}