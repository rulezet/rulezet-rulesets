rule TTP_XOR_WriteProcessMemory_2a23 {
  strings:
    $key_2a23 = { 7d 51 [2] 4f 73 [2] 49 46 [2] 67 46 [2] 58 5a }

  condition:
    any of them
}