rule TTP_XOR_WriteProcessMemory_3303 {
  strings:
    $key_3303 = { 64 71 [2] 56 53 [2] 50 66 [2] 7e 66 [2] 41 7a }

  condition:
    any of them
}