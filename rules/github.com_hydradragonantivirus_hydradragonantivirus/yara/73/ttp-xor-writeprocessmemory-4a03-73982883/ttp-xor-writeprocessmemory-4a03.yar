rule TTP_XOR_WriteProcessMemory_4a03 {
  strings:
    $key_4a03 = { 1d 71 [2] 2f 53 [2] 29 66 [2] 07 66 [2] 38 7a }

  condition:
    any of them
}