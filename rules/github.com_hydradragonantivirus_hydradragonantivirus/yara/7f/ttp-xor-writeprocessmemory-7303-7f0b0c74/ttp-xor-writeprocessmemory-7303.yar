rule TTP_XOR_WriteProcessMemory_7303 {
  strings:
    $key_7303 = { 24 71 [2] 16 53 [2] 10 66 [2] 3e 66 [2] 01 7a }

  condition:
    any of them
}