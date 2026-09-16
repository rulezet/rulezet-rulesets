rule TTP_XOR_WriteProcessMemory_0103 {
  strings:
    $key_0103 = { 56 71 [2] 64 53 [2] 62 66 [2] 4c 66 [2] 73 7a }

  condition:
    any of them
}