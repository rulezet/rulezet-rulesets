rule TTP_XOR_WriteProcessMemory_1a23 {
  strings:
    $key_1a23 = { 4d 51 [2] 7f 73 [2] 79 46 [2] 57 46 [2] 68 5a }

  condition:
    any of them
}