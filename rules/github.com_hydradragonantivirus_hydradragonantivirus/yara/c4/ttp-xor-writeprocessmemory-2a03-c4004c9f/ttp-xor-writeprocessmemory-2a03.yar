rule TTP_XOR_WriteProcessMemory_2a03 {
  strings:
    $key_2a03 = { 7d 71 [2] 4f 53 [2] 49 66 [2] 67 66 [2] 58 7a }

  condition:
    any of them
}