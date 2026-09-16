rule TTP_XOR_WriteProcessMemory_4103 {
  strings:
    $key_4103 = { 16 71 [2] 24 53 [2] 22 66 [2] 0c 66 [2] 33 7a }

  condition:
    any of them
}