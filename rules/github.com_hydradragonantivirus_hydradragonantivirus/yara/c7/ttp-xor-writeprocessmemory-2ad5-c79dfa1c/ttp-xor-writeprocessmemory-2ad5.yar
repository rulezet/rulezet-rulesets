rule TTP_XOR_WriteProcessMemory_2ad5 {
  strings:
    $key_2ad5 = { 7d a7 [2] 4f 85 [2] 49 b0 [2] 67 b0 [2] 58 ac }

  condition:
    any of them
}