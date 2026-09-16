rule TTP_XOR_WriteProcessMemory_0370 {
  strings:
    $key_0370 = { 54 02 [2] 66 20 [2] 60 15 [2] 4e 15 [2] 71 09 }

  condition:
    any of them
}