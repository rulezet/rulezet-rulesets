rule TTP_XOR_WriteProcessMemory_7447 {
  strings:
    $key_7447 = { 23 35 [2] 11 17 [2] 17 22 [2] 39 22 [2] 06 3e }

  condition:
    any of them
}