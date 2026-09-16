rule TTP_XOR_WriteProcessMemory_7f03 {
  strings:
    $key_7f03 = { 28 71 [2] 1a 53 [2] 1c 66 [2] 32 66 [2] 0d 7a }

  condition:
    any of them
}