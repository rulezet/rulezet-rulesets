rule TTP_XOR_WriteProcessMemory_6221 {
  strings:
    $key_6221 = { 35 53 [2] 07 71 [2] 01 44 [2] 2f 44 [2] 10 58 }

  condition:
    any of them
}