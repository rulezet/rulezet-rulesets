rule TTP_XOR_WriteProcessMemory_1903 {
  strings:
    $key_1903 = { 4e 71 [2] 7c 53 [2] 7a 66 [2] 54 66 [2] 6b 7a }

  condition:
    any of them
}