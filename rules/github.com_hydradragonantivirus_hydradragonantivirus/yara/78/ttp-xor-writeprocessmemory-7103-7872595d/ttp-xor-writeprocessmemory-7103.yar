rule TTP_XOR_WriteProcessMemory_7103 {
  strings:
    $key_7103 = { 26 71 [2] 14 53 [2] 12 66 [2] 3c 66 [2] 03 7a }

  condition:
    any of them
}