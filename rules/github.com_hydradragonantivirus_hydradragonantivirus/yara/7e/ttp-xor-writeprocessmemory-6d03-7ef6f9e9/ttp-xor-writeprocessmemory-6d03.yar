rule TTP_XOR_WriteProcessMemory_6d03 {
  strings:
    $key_6d03 = { 3a 71 [2] 08 53 [2] 0e 66 [2] 20 66 [2] 1f 7a }

  condition:
    any of them
}