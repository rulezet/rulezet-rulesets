rule TTP_XOR_WriteProcessMemory_0150 {
  strings:
    $key_0150 = { 56 22 [2] 64 00 [2] 62 35 [2] 4c 35 [2] 73 29 }

  condition:
    any of them
}