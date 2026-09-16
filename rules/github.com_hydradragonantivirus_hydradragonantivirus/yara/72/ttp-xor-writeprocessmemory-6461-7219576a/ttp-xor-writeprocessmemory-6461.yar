rule TTP_XOR_WriteProcessMemory_6461 {
  strings:
    $key_6461 = { 33 13 [2] 01 31 [2] 07 04 [2] 29 04 [2] 16 18 }

  condition:
    any of them
}