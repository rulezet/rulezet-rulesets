rule TTP_XOR_WriteProcessMemory_0141 {
  strings:
    $key_0141 = { 56 33 [2] 64 11 [2] 62 24 [2] 4c 24 [2] 73 38 }

  condition:
    any of them
}