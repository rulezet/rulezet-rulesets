rule TTP_XOR_WriteProcessMemory_7161 {
  strings:
    $key_7161 = { 26 13 [2] 14 31 [2] 12 04 [2] 3c 04 [2] 03 18 }

  condition:
    any of them
}