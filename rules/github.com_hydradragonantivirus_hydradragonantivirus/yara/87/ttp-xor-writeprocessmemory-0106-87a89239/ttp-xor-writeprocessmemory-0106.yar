rule TTP_XOR_WriteProcessMemory_0106 {
  strings:
    $key_0106 = { 56 74 [2] 64 56 [2] 62 63 [2] 4c 63 [2] 73 7f }

  condition:
    any of them
}