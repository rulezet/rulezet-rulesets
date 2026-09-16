rule TTP_XOR_WriteProcessMemory_1103 {
  strings:
    $key_1103 = { 46 71 [2] 74 53 [2] 72 66 [2] 5c 66 [2] 63 7a }

  condition:
    any of them
}