rule TTP_XOR_WriteProcessMemory_0160 {
  strings:
    $key_0160 = { 56 12 [2] 64 30 [2] 62 05 [2] 4c 05 [2] 73 19 }

  condition:
    any of them
}