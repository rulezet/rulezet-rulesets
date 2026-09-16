rule TTP_XOR_WriteProcessMemory_c951 {
  strings:
    $key_c951 = { 9e 23 [2] ac 01 [2] aa 34 [2] 84 34 [2] bb 28 }

  condition:
    any of them
}