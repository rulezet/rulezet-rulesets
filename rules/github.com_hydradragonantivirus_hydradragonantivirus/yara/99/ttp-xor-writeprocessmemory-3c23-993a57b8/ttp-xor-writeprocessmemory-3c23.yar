rule TTP_XOR_WriteProcessMemory_3c23 {
  strings:
    $key_3c23 = { 6b 51 [2] 59 73 [2] 5f 46 [2] 71 46 [2] 4e 5a }

  condition:
    any of them
}