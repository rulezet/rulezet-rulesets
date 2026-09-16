rule TTP_XOR_WriteProcessMemory_0403 {
  strings:
    $key_0403 = { 53 71 [2] 61 53 [2] 67 66 [2] 49 66 [2] 76 7a }

  condition:
    any of them
}